#include "Polyweb/polyweb.hpp"
#include "json.hpp"
#include "theme.hpp"
#include "toml.hpp"
#include "util.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_File_Chooser.H>
#include <FL/Fl_Flex.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Hor_Slider.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Scroll.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Spinner.H>
#include <FL/fl_ask.H>
#include <FL/fl_callback_macros.H>
#include <FL/fl_draw.H>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#ifdef _WIN32
    #include <FL/platform.H>
    #include <ios>
    #include <shellapi.h>
    #include <windows.h>
#else
    #include <chrono>
    #include <errno.h>
    #include <signal.h>
    #include <sys/wait.h>
    #include <thread>
    #include <unistd.h>
#endif

using nlohmann::json;

// A right-aligned form label that sizes itself to its text, so the field column
// lines up regardless of font or scaling factor
class Label : public Fl_Box {
public:
    Label(int x, int y, const char* text):
        Fl_Box(x, y, 0, 0, text) {
        int width = 0, height = 0;
        fl_font(labelfont(), labelsize());
        fl_measure(text, width, height);
        size(width + 4, height);
        align(FL_ALIGN_RIGHT | FL_ALIGN_INSIDE);
    }
};

static Fl_Button* accent_button(Fl_Button* button) {
    button->color(TENEBRA_ACCENT);
    button->selection_color(TENEBRA_ACCENT_PRESSED);
    button->labelcolor(FL_WHITE);
    return button;
}

static Fl_Button* danger_button(Fl_Button* button) {
    button->color(TENEBRA_DANGER);
    button->selection_color(TENEBRA_DANGER_PRESSED);
    button->labelcolor(FL_WHITE);
    return button;
}

class MainWindow : public Fl_Double_Window {
protected:
    Fl_Box* status_label;
    Fl_Button* start_button;
    Fl_Button* stop_button;
    Fl_Button* restart_button;
    Fl_Button* share_button;
    Fl_Button* save_button;

    Fl_Secret_Input* password_input;
    Fl_Spinner* port_spinner;
    Fl_Spinner* target_bitrate_spinner;
    Fl_Spinner* windows_monitor_index_spinner;
    Fl_Choice* windows_capture_api_choice;
    Fl_Hor_Slider* windows_quality_vs_speed_slider;
    Fl_Group* windows_quality_vs_speed_row;
    Fl_Spinner* startx_spinner;
    Fl_Spinner* starty_spinner;
    Fl_Spinner* endx_spinner;
    Fl_Check_Button* endx_check_button;
    Fl_Spinner* endy_spinner;
    Fl_Check_Button* endy_check_button;
    Fl_Spinner* vbv_buf_capacity_spinner;
    Fl_Check_Button* tcp_upnp_check_button;
    Fl_Check_Button* sound_forwarding_check_button;
    Fl_Check_Button* hwencode_check_button;
    Fl_Check_Button* vapostproc_check_button;
    Fl_Check_Button* color_downsampling_check_button;
    Fl_Check_Button* bwe_check_button;
    Fl_Input* cert_input;
    Fl_Input* key_input;

    // Rows that only apply on Windows, kept so they can be hidden elsewhere
    Fl_Group* windows_monitor_index_row;
    Fl_Group* windows_capture_api_row;
    Fl_Group* vapostproc_row;
    Fl_Flex* page;
    Fl_Flex* status_row;

    bool new_user = false;
    bool dirty = true;

    static void handle_change(Fl_Widget*, void* data) {
        ((MainWindow*) data)->set_dirty(true);
    }

    // Fl_Group holding a right-aligned label and one field, sized in text units so
    // that everything scales with the font rather than with hardcoded pixels
    Fl_Flex* row(const char* text) {
        auto group = new Fl_Flex(Fl_Flex::ROW);
        group->gap(6);
        auto label = new Label(0, 0, text);
        group->fixed(label, label_width);
        return group;
    }

public:
    static constexpr int label_width = 190;
    static constexpr int row_height = 30;

    MainWindow(int width, int height):
        Fl_Double_Window(width, height, "Tenebra") {
        auto root = new Fl_Flex(10, 10, width - 20, height - 20, Fl_Flex::COLUMN);
        root->gap(10);

        // ---- status strip: what the app is doing, and the controls that change it ----
        status_row = new Fl_Flex(Fl_Flex::ROW);
        status_row->gap(6);
        status_label = new Fl_Box(0, 0, 0, 0, "");
        status_label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        status_label->labelfont(FL_HELVETICA_BOLD);

        share_button = new Fl_Button(0, 0, 90, 0, "Share...");
        FL_INLINE_CALLBACK_1(share_button, MainWindow*, window, this, {
            window->handle_share();
        });
        status_row->fixed(share_button, share_button->w());

        restart_button = new Fl_Button(0, 0, 80, 0, "Restart");
        FL_INLINE_CALLBACK_1(restart_button, MainWindow*, window, this, {
            if (!window->stop(false) && !window->start()) {
                fl_message("Tenebra has been restarted");
            }
            window->refresh_status();
        });
        status_row->fixed(restart_button, restart_button->w());

        start_button = accent_button(new Fl_Button(0, 0, 80, 0, "Start"));
        FL_INLINE_CALLBACK_1(start_button, MainWindow*, window, this, {
            window->start();
            window->refresh_status();
        });
        status_row->fixed(start_button, start_button->w());

        stop_button = danger_button(new Fl_Button(0, 0, 80, 0, "Stop"));
        FL_INLINE_CALLBACK_1(stop_button, MainWindow*, window, this, {
            window->stop();
            window->refresh_status();
        });
        status_row->fixed(stop_button, stop_button->w());

        status_row->end();
        root->fixed(status_row, 34);

        // ---- settings ----
        auto scroll = new Fl_Scroll(0, 0, 0, 0);
        scroll->type(Fl_Scroll::VERTICAL);
        scroll->box(FL_NO_BOX);

        page = new Fl_Flex(0, 0, width - 40, 10, Fl_Flex::COLUMN);
        page->gap(6);

        {
            auto r = row("Password: ");
            password_input = new Fl_Secret_Input(0, 0, 0, 0);
            password_input->callback(handle_change, this);
            password_input->when(FL_WHEN_CHANGED);
            r->end();
        }
        {
            auto r = row("Port: ");
            port_spinner = new Fl_Spinner(0, 0, 0, 0);
            port_spinner->type(FL_INT_INPUT);
            port_spinner->range(0, 65535);
            port_spinner->value(8080);
            port_spinner->callback(handle_change, this);
            r->fixed(port_spinner, 110);
            r->end();
        }
        {
            auto r = row("Target bitrate (kbps): ");
            target_bitrate_spinner = new Fl_Spinner(0, 0, 0, 0);
            target_bitrate_spinner->type(FL_INT_INPUT);
            target_bitrate_spinner->range(50, 12000);
            target_bitrate_spinner->value(4000);
            target_bitrate_spinner->callback(handle_change, this);
            r->fixed(target_bitrate_spinner, 110);
            r->end();
        }
        {
            auto r = row("Monitor index: ");
            windows_monitor_index_spinner = new Fl_Spinner(0, 0, 0, 0);
            windows_monitor_index_spinner->type(FL_INT_INPUT);
            windows_monitor_index_spinner->range(-1, 65535);
            windows_monitor_index_spinner->value(-1);
            windows_monitor_index_spinner->tooltip("The index of the monitor to capture (-1 = primary monitor)");
            windows_monitor_index_spinner->callback(handle_change, this);
            r->fixed(windows_monitor_index_spinner, 110);
            r->end();
            windows_monitor_index_row = r;
        }
        {
            auto r = row("Screen capture API: ");
            windows_capture_api_choice = new Fl_Choice(0, 0, 0, 0);
            windows_capture_api_choice->add("DXGI");
            windows_capture_api_choice->add("WGC");
            windows_capture_api_choice->value(0);
            windows_capture_api_choice->tooltip("DXGI is more compatible, but WGC is newer and more modern");
            windows_capture_api_choice->callback(handle_change, this);
            r->fixed(windows_capture_api_choice, 140);
            r->end();
            windows_capture_api_row = r;
        }
        {
            auto r = row("Quality vs. speed: ");
            windows_quality_vs_speed_slider = new Fl_Hor_Slider(0, 0, 0, 0);
            windows_quality_vs_speed_slider->range(0, 100);
            windows_quality_vs_speed_slider->step(1);
            windows_quality_vs_speed_slider->value(50);
            windows_quality_vs_speed_slider->tooltip("0 = high speed and low quality, 100 = high quality and low speed");
            windows_quality_vs_speed_slider->callback(handle_change, this);
            r->end();
            windows_quality_vs_speed_row = r;
        }
        {
            auto r = row("Start x: ");
            startx_spinner = new Fl_Spinner(0, 0, 0, 0);
            startx_spinner->type(FL_INT_INPUT);
            startx_spinner->range(0, 65535);
            startx_spinner->value(0);
            startx_spinner->tooltip("The x-coordinate to start streaming at");
            startx_spinner->callback(handle_change, this);
            r->fixed(startx_spinner, 110);
            r->end();
        }
        {
            auto r = row("Start y: ");
            starty_spinner = new Fl_Spinner(0, 0, 0, 0);
            starty_spinner->type(FL_INT_INPUT);
            starty_spinner->range(0, 65535);
            starty_spinner->value(0);
            starty_spinner->tooltip("The y-coordinate to start streaming at");
            starty_spinner->callback(handle_change, this);
            r->fixed(starty_spinner, 110);
            r->end();
        }
        {
            auto r = row("End x: ");
            endx_spinner = new Fl_Spinner(0, 0, 0, 0);
            endx_spinner->type(FL_INT_INPUT);
            endx_spinner->range(0, 65535);
            endx_spinner->value(0);
            endx_spinner->tooltip("The x-coordinate to stop streaming at");
            endx_spinner->deactivate();
            endx_spinner->callback(handle_change, this);
            auto endx_check = new Fl_Check_Button(0, 0, 0, 0, "Limit");
            endx_check_button = endx_check;
            // The macro expands to a static function, so every widget it touches has
            // to be passed in explicitly -- members are not in scope
            FL_INLINE_CALLBACK_3(endx_check, MainWindow*, window, this, Fl_Spinner*, spinner, endx_spinner, Fl_Check_Button*, check, endx_check, {
                if (check->value()) {
                    spinner->activate();
                } else {
                    spinner->deactivate();
                }
                window->set_dirty(true);
            });
            r->fixed(endx_spinner, 110);
            r->fixed(endx_check_button, 70);
            r->end();
        }
        {
            auto r = row("End y: ");
            endy_spinner = new Fl_Spinner(0, 0, 0, 0);
            endy_spinner->type(FL_INT_INPUT);
            endy_spinner->range(0, 65535);
            endy_spinner->value(0);
            endy_spinner->tooltip("The y-coordinate to stop streaming at");
            endy_spinner->deactivate();
            endy_spinner->callback(handle_change, this);
            auto endy_check = new Fl_Check_Button(0, 0, 0, 0, "Limit");
            endy_check_button = endy_check;
            FL_INLINE_CALLBACK_3(endy_check, MainWindow*, window, this, Fl_Spinner*, spinner, endy_spinner, Fl_Check_Button*, check, endy_check, {
                if (check->value()) {
                    spinner->activate();
                } else {
                    spinner->deactivate();
                }
                window->set_dirty(true);
            });
            r->fixed(endy_spinner, 110);
            r->fixed(endy_check_button, 70);
            r->end();
        }
        {
            auto r = row("VBV buffer capacity (ms): ");
            vbv_buf_capacity_spinner = new Fl_Spinner(0, 0, 0, 0);
            vbv_buf_capacity_spinner->type(FL_INT_INPUT);
            vbv_buf_capacity_spinner->range(1, 1000);
            vbv_buf_capacity_spinner->value(120);
            vbv_buf_capacity_spinner->tooltip("The size of the video buffering verifier (VBV) buffer, which controls how smoothly bitrate is distributed to prevent playback stuttering or quality drops");
            vbv_buf_capacity_spinner->callback(handle_change, this);
            r->fixed(vbv_buf_capacity_spinner, 110);
            r->end();
        }

        auto check_row = [&](Fl_Check_Button*& out, const char* text, const char* tip, bool on) {
            auto r = new Fl_Flex(Fl_Flex::ROW);
            auto spacer = new Fl_Box(0, 0, 0, 0);
            r->fixed(spacer, label_width);
            out = new Fl_Check_Button(0, 0, 0, 0, text);
            out->value(on);
            if (tip) out->tooltip(tip);
            out->callback(handle_change, this);
            r->end();
            return r;
        };

        check_row(tcp_upnp_check_button, "Automatic ICE-TCP UPnP forwarding",
            "Automatically forwards TCP ports for ICE-TCP", true);
        check_row(sound_forwarding_check_button, "Sound forwarding", nullptr, true);
        check_row(hwencode_check_button, "Hardware-accelerated video encoding",
#ifdef _WIN32
            "Uses Microsoft Media Foundation for video encoding and conversion",
#elif defined(__APPLE__)
            "Uses Apple VideoToolbox for video encoding and conversion",
#else
            "Uses VA-API on devices with Intel or AMD GPUs",
#endif
            false);
        vapostproc_row = check_row(vapostproc_check_button, "VA-API video conversion",
            "Enables hardware accelerated video format conversion on devices with Intel or AMD GPUs", false);
        vapostproc_check_button->deactivate();
        check_row(color_downsampling_check_button, "Color channel downsampling",
            "Encodes frames in NV12 format", true);
        check_row(bwe_check_button, "Bandwidth estimation",
            "Adjusts media bitrate on the fly to adapt to changing network conditions", true);

        // hwencode gates several other settings, exactly as the GTK version did
        FL_INLINE_CALLBACK_1(hwencode_check_button, MainWindow*, window, this, {
            window->apply_hwencode_state();
            window->set_dirty(true);
        });

        {
            auto r = row("TLS certificate: ");
            cert_input = new Fl_Input(0, 0, 0, 0);
            cert_input->callback(handle_change, this);
            cert_input->when(FL_WHEN_CHANGED);
            auto browse = new Fl_Button(0, 0, 0, 0, "...");
            FL_INLINE_CALLBACK_1(browse, Fl_Input*, input, cert_input, {
                if (const char* path = fl_file_chooser("Choose a certificate", "PEM Files (*.pem)", input->value())) {
                    input->value(path);
                    input->do_callback();
                }
            });
            r->fixed(browse, 40);
            r->end();
        }
        {
            auto r = row("Private key: ");
            key_input = new Fl_Input(0, 0, 0, 0);
            key_input->callback(handle_change, this);
            key_input->when(FL_WHEN_CHANGED);
            auto browse = new Fl_Button(0, 0, 0, 0, "...");
            FL_INLINE_CALLBACK_1(browse, Fl_Input*, input, key_input, {
                if (const char* path = fl_file_chooser("Choose a private key", "PEM Files (*.pem)", input->value())) {
                    input->value(path);
                    input->do_callback();
                }
            });
            r->fixed(browse, 40);
            r->end();
        }

        page->end();
        scroll->end();
        scroll->resizable(nullptr);

        // ---- commit actions ----
        auto button_row = new Fl_Flex(Fl_Flex::ROW);
        button_row->gap(6);
        auto refresh_button = new Fl_Button(0, 0, 90, 0, "Revert");
        FL_INLINE_CALLBACK_1(refresh_button, MainWindow*, window, this, {
            window->refresh(true);
        });
        button_row->fixed(refresh_button, refresh_button->w());
        new Fl_Box(0, 0, 0, 0); // spacer
        save_button = accent_button(new Fl_Button(0, 0, 90, 0, "Save"));
        FL_INLINE_CALLBACK_1(save_button, MainWindow*, window, this, {
            window->save();
        });
        button_row->fixed(save_button, save_button->w());
        button_row->end();
        root->fixed(button_row, 30);

        root->end();
        resizable(root);
        end();

        // Settings that only apply on Windows are hidden elsewhere, matching the
        // GTK version's behaviour
#ifdef _WIN32
        vapostproc_row->hide();
#elif defined(__APPLE__)
        windows_monitor_index_row->hide();
        windows_capture_api_row->hide();
        windows_quality_vs_speed_row->hide();
        sound_forwarding_check_button->parent()->hide();
        vapostproc_row->hide();
#else
        windows_monitor_index_row->hide();
        windows_capture_api_row->hide();
        windows_quality_vs_speed_row->hide();
#endif

        layout_page();
        refresh();
        Fl::add_timeout(2.0, poll_status, this);
    }

    // Fl_Flex has no natural height, so the scrolled page is sized from its visible
    // rows. Hidden rows take no space in Fl_Flex, so they must not be counted here
    void layout_page() {
        int visible_rows = 0;
        for (int i = 0; i < page->children(); i++) {
            if (page->child(i)->visible()) visible_rows++;
        }
        page->size(page->w(), visible_rows * row_height + (visible_rows - 1) * page->gap());
        page->layout();
    }

    void set_dirty(bool value) {
        dirty = value;
        if (dirty) {
            save_button->activate();
        } else {
            save_button->deactivate();
        }
    }

    void apply_hwencode_state() {
        if (hwencode_check_button->value()) {
#ifdef _WIN32
            windows_quality_vs_speed_slider->activate();
#elif defined(__APPLE__)
            vbv_buf_capacity_spinner->deactivate();
            bwe_check_button->deactivate();
            bwe_check_button->value(0);
#else
            vapostproc_check_button->activate();
#endif
            color_downsampling_check_button->deactivate();
            color_downsampling_check_button->value(1);
        } else {
#ifdef _WIN32
            windows_quality_vs_speed_slider->deactivate();
#elif defined(__APPLE__)
            vbv_buf_capacity_spinner->activate();
            bwe_check_button->activate();
#else
            vapostproc_check_button->deactivate();
            vapostproc_check_button->value(0);
#endif
            color_downsampling_check_button->activate();
        }
    }

    static void poll_status(void* data) {
        auto window = (MainWindow*) data;
        if (window->visible()) {
            window->refresh_status();
        }
        Fl::repeat_timeout(2.0, poll_status, data);
    }

    void refresh_status() {
        if (get_tenebra_pid() == -1) {
            status_label->copy_label("  Tenebra is not running");
            start_button->show();
            stop_button->hide();
            restart_button->hide();
        } else {
            status_label->copy_label(("  Running on port " + std::to_string((unsigned short) port_spinner->value())).c_str());
            start_button->hide();
            stop_button->show();
            restart_button->show();
        }
        // Fl_Flex does not re-flow when a child's visibility changes, so the row
        // would keep the geometry it had when the other buttons were shown
        status_row->layout();
        redraw();
    }

    void handle_share() {
        std::string address = get_common_name_from_cert(cert_input->value()) + ':' + std::to_string((unsigned short) port_spinner->value());

        auto dialog = new Fl_Double_Window(360, 150, "Share");
        dialog->set_modal();
        auto flex = new Fl_Flex(10, 10, 340, 130, Fl_Flex::COLUMN);
        flex->gap(8);

        auto address_row = new Fl_Flex(Fl_Flex::ROW);
        address_row->gap(6);
        auto address_label = new Label(0, 0, "Address: ");
        auto address_input = new Fl_Input(0, 0, 0, 0);
        address_input->value(address.c_str());
        address_row->fixed(address_label, address_label->w());
        address_row->end();

        auto view_only = new Fl_Check_Button(0, 0, 0, 0, "View only");

        auto buttons = new Fl_Flex(Fl_Flex::ROW);
        buttons->gap(6);
        new Fl_Box(0, 0, 0, 0);
        auto cancel = new Fl_Button(0, 0, 90, 0, "Cancel");
        FL_INLINE_CALLBACK_1(cancel, Fl_Double_Window*, dialog, dialog, {
            dialog->hide();
        });
        buttons->fixed(cancel, cancel->w());
        auto copy = accent_button(new Fl_Button(0, 0, 150, 0, "Copy One-Time Link"));
        FL_INLINE_CALLBACK_3(copy, MainWindow*, window, this, Fl_Input*, address_input, address_input, Fl_Check_Button*, view_only, view_only, {
            window->copy_one_time_link(address_input->value(), view_only->value());
        });
        buttons->fixed(copy, copy->w());
        buttons->end();

        flex->fixed(address_row, 28);
        flex->fixed(view_only, 24);
        flex->fixed(buttons, 30);
        flex->end();
        dialog->end();
        dialog->show();
    }

    void copy_one_time_link(const char* address, bool view_only) {
        json req_json = {
            {"password", password_input->value()},
            {"view_only", view_only},
        };

        pn::TLSContext tls_context;
        if (pn::Status result = tls_context.init_client(SSL_VERIFY_NONE); !result) {
            fl_alert("Failed to create one-time link key: %s", result.error().message().c_str());
            return;
        }

        pw::Response resp;
        if (pn::Status result = pw::fetch("POST", "https://localhost:" + std::to_string((unsigned short) port_spinner->value()) + "/create_key", resp, req_json.dump(), {{"Content-Type", "application/json"}}, {.tls_context = &tls_context}); !result) {
            fl_alert("Failed to create one-time link key: %s", result.error().message().c_str());
            return;
        } else if (resp.status_code != 200) {
            fl_alert("Failed to create one-time link key: Response has status code %d", (int) resp.status_code);
            return;
        }

        pw::URLInfo url_info;
        url_info.scheme = "https";
        url_info.host = "audacia.duckdns.org";
        *url_info.query_parameters = {
            {"address", address},
            {"key", resp.body_string()},
            {"view_only", view_only ? "true" : "false"},
        };
        std::string url = url_info.build();
        Fl::copy(url.c_str(), url.size(), 1);
        fl_message("Copied one-time access link to clipboard");
    }

    void refresh(bool confirm = false) {
        if (confirm && dirty) {
            switch (fl_choice("You have unsaved changes. Changes that are not saved will be permanently lost.", "Cancel", "Save", "Discard")) {
            case 1:
                save();
                refresh_status();
                return;

            case 2:
                break;

            default:
                return;
            }
        }

        refresh_status();

        auto config_path = get_config_path();
        if (!config_path.empty()) {
            if (!std::filesystem::exists(config_path / "config.toml")) {
                if (!std::filesystem::exists(config_path)) {
                    std::filesystem::create_directory(config_path);
                }
                new_user = true;
                return;
            }

            try {
                auto config = toml::parse(config_path / "config.toml");

                auto password = toml::find<std::string>(config, "password");
                auto port = toml::find<unsigned short>(config, "port");
                auto target_bitrate = toml::find<unsigned int>(config, "target_bitrate");
                auto windows_monitor_index = toml::find_or<int>(config, "windows_monitor_index", -1);
                auto windows_capture_api = toml::find_or<std::string>(config, "windows_capture_api", "dxgi");
                auto windows_quality_vs_speed = toml::find_or<unsigned short>(config, "windows_quality_vs_speed", 50);
                auto startx = toml::find<unsigned short>(config, "startx");
                auto starty = toml::find_or<unsigned short>(config, "starty", 0);
                auto vbv_buf_capacity = toml::find_or<unsigned short>(config, "vbv_buf_capacity", 120);
                auto tcp_upnp = toml::find<bool>(config, "tcp_upnp");
                auto sound_forwarding = toml::find<bool>(config, "sound_forwarding");
                auto hwencode = toml::find_or<bool>(config, "hwencode", toml::find_or<bool>(config, "vaapi", false));
                auto vapostproc = toml::find<bool>(config, "vapostproc");
                auto full_chroma = toml::find<bool>(config, "full_chroma");
                auto no_bwe = toml::find<bool>(config, "no_bwe");
                auto cert = toml::find<std::string>(config, "cert");
                auto key = toml::find<std::string>(config, "key");

                password_input->value(password.c_str());
                port_spinner->value(port);
                target_bitrate_spinner->value(target_bitrate);
                windows_monitor_index_spinner->value(windows_monitor_index);
                windows_capture_api_choice->value(windows_capture_api == "wgc" ? 1 : 0);
                windows_quality_vs_speed_slider->value(windows_quality_vs_speed);
                startx_spinner->value(startx);
                starty_spinner->value(starty);
                vbv_buf_capacity_spinner->value(vbv_buf_capacity);
                tcp_upnp_check_button->value(tcp_upnp);
                sound_forwarding_check_button->value(sound_forwarding);
                hwencode_check_button->value(hwencode);
                vapostproc_check_button->value(vapostproc);
                color_downsampling_check_button->value(!full_chroma);
                bwe_check_button->value(!no_bwe);
                cert_input->value(cert.c_str());
                key_input->value(key.c_str());
                apply_hwencode_state();

                if (config.contains("endx")) {
                    endx_spinner->value(toml::find<unsigned short>(config, "endx"));
                    endx_check_button->value(1);
                    endx_spinner->activate();
                } else {
                    endx_check_button->value(0);
                    endx_spinner->deactivate();
                }

                if (config.contains("endy")) {
                    endy_spinner->value(toml::find<unsigned short>(config, "endy"));
                    endy_check_button->value(1);
                    endy_spinner->activate();
                } else {
                    endy_check_button->value(0);
                    endy_spinner->deactivate();
                }

                set_dirty(false);
                redraw();
            } catch (...) {
                fl_alert("Failed to parse existing settings at %s", (config_path / "config.toml").string().c_str());
            }
        }
    }

    int start() {
        if (save(false) == -1) return -1;

#ifdef _WIN32
        SC_HANDLE sc_manager;
        if (!(sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT))) {
            fl_alert("Failed to start Tenebra (OpenSCManager failed, error %lu)", GetLastError());
            return -1;
        }

        SC_HANDLE service;
        if (!(service = OpenService(sc_manager, "Tenebra", SERVICE_START))) {
            fl_alert("Failed to start Tenebra (OpenService failed, error %lu)", GetLastError());
            CloseServiceHandle(sc_manager);
            return -1;
        }

        if (!StartService(service, 0, nullptr)) {
            fl_alert("Failed to start Tenebra (StartService failed, error %lu)", GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return -1;
        }

        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
#else
        int pipe_fds[2];
        if (pipe(pipe_fds) == -1) {
            fl_alert("Failed to start Tenebra (pipe failed, error %d)", errno);
            return -1;
        }

        if (pid_t pid = fork(); pid == -1) {
            fl_alert("Failed to start Tenebra (fork failed, error %d)", errno);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return -1;
        } else if (!pid) {
            close(pipe_fds[0]); // Close unused read end
            fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

            int null_fd;
            if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
                int error = errno;
                write(pipe_fds[1], &error, sizeof(int));
                close(pipe_fds[1]);
                exit(EXIT_FAILURE);
            }
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);

            setsid();
            if (execlp("tenebra", "tenebra", nullptr) == -1) {
                int error = errno;
                write(pipe_fds[1], &error, sizeof(int));
                close(pipe_fds[1]);
                exit(EXIT_FAILURE);
            }
        }

        close(pipe_fds[1]); // Close unused write end

        int error;
        if (read(pipe_fds[0], &error, sizeof(int)) == sizeof(int)) {
            fl_alert("Failed to start Tenebra (error %d)", error);
            close(pipe_fds[0]);
            return -1;
        }

        close(pipe_fds[0]);
#endif
        return 0;
    }

    int stop(bool show_not_running_message = true) {
        if (pid_t pid = get_tenebra_pid(); pid != -1) {
#ifdef _WIN32
            HANDLE process;
            if ((process = OpenProcess(PROCESS_TERMINATE, FALSE, pid)) == nullptr) {
                fl_alert("Failed to stop Tenebra (OpenProcess failed, error %lu)", GetLastError());
                return -1;
            }
            if (!TerminateProcess(process, 1)) {
                fl_alert("Failed to stop Tenebra (TerminateProcess failed, error %lu)", GetLastError());
                CloseHandle(process);
                return -1;
            }
            CloseHandle(process);
#else
            if (kill(pid, SIGTERM) == -1) {
                fl_alert("Failed to stop Tenebra (kill failed, error %d)", errno);
                return -1;
            }

            // Wait for Tenebra to die
            for (;; std::this_thread::sleep_for(std::chrono::milliseconds(10))) {
                if (kill(pid, 0) == -1 && errno == ESRCH) {
                    break;
                }
            }
#endif
        } else if (show_not_running_message) {
            fl_message("Tenebra wasn't running in the first place \xf0\x9f\xab\xa4");
        }
        return 0;
    }

    int save(bool show_success_message = true) {
        auto config_path = get_config_path();
        if (!config_path.empty()) {
            if (!std::filesystem::exists(config_path)) {
                std::filesystem::create_directory(config_path);
            }

            std::ofstream config_file(config_path / "config.toml");
            if (config_file.is_open()) {
                toml::value config({
                    {"password", password_input->value()},
                    {"port", (unsigned short) port_spinner->value()},
                    {"target_bitrate", (unsigned int) target_bitrate_spinner->value()},
                    {"windows_monitor_index", (int) windows_monitor_index_spinner->value()},
                    {"windows_capture_api", pw::string::to_lower_copy(windows_capture_api_choice->text(windows_capture_api_choice->value()))},
                    {"windows_quality_vs_speed", (unsigned short) windows_quality_vs_speed_slider->value()},
                    {"startx", (unsigned short) startx_spinner->value()},
                    {"starty", (unsigned short) starty_spinner->value()},
                    {"vbv_buf_capacity", (unsigned short) vbv_buf_capacity_spinner->value()},
                    {"tcp_upnp", (bool) tcp_upnp_check_button->value()},
                    {"sound_forwarding", (bool) sound_forwarding_check_button->value()},
                    {"hwencode", (bool) hwencode_check_button->value()},
                    {"vapostproc", (bool) vapostproc_check_button->value()},
                    {"full_chroma", !color_downsampling_check_button->value()},
                    {"no_bwe", !bwe_check_button->value()},
                    {"cert", cert_input->value()},
                    {"key", key_input->value()},
                });
                if (endx_check_button->value()) {
                    config["endx"] = (unsigned short) endx_spinner->value();
                }
                if (endy_check_button->value()) {
                    config["endy"] = (unsigned short) endy_spinner->value();
                }

                if (config_file << config << std::flush) {
                    set_dirty(false);
                    if (show_success_message) {
                        fl_message("Settings saved to %s", (config_path / "config.toml").string().c_str());
                    }
                    return 0;
                }
            }
        }

        fl_alert("Failed to save settings to %s", (config_path / "config.toml").string().c_str());
        return -1;
    }

    bool is_new_user() const {
        return new_user;
    }
};

int main(int argc, char* argv[]) {
    pw::thread_pool.resize(0);
#ifdef _WIN32
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);
        std::ios::sync_with_stdio();
    }

    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (PSID admin_group; AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    if (!is_admin) {
        SHELLEXECUTEINFO info = {.cbSize = sizeof(SHELLEXECUTEINFO)};
        info.lpVerb = "runas";
        info.lpFile = argv[0];
        info.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteEx(&info)) {
            MessageBox(nullptr, "This program must be run with elevated privileges to allow Tenebra to interact with other elevated programs.", "Error", MB_OK | MB_ICONERROR);
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
#else
    signal(SIGCHLD, [](int) {
        waitpid(-1, nullptr, WNOHANG);
    });
#endif

    (void) pn::init();

    // Fl_Window::show(argc, argv) calls Fl::get_system_colors(), which re-reads the
    // system palette and reinstalls the scheme's box types, undoing the theme. Parse
    // the arguments separately and use the plain show() so the theme survives
    Fl::args(argc, argv);

    configure_fltk_colors();
    fl_message_hotspot(0);

    auto window = new MainWindow(680, 700);
    window->size_range(560, 400);
    window->show();
#ifdef _WIN32
    set_window_dark_mode(fl_win32_xid(window));
#endif

    if (window->is_new_user()) {
        fl_message("Welcome to Tenebra! Here, you can configure Tenebra's settings. "
                   "Before starting, make sure you've set a password and directed it to your TLS certificate.");
    }

    int ret = Fl::run();
    (void) pn::quit();
    return ret;
}
