#include "Polyweb/polyweb.hpp"
#include "glib.hpp"
#include "json.hpp"
#include "toml.hpp"
#include "util.hpp"
#include <adwaita.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#ifdef _WIN32
    #include <ios>
    #include <shellapi.h>
    #include <shellscalingapi.h>
    #include <windows.h>
#else
    #include <errno.h>
    #include <signal.h>
    #include <sys/wait.h>
    #include <thread>
    #include <unistd.h>
#endif

using nlohmann::json;

class MainWindow {
protected:
    // All null until handle_activate builds them, so that a signal handler firing
    // mid-construction hits a null check rather than an indeterminate pointer
    GtkWidget* window = nullptr;
    GtkWidget* toast_overlay = nullptr;

    GtkWidget* button_stack = nullptr;
    GtkWidget* start_button = nullptr;
    GtkWidget* running_box = nullptr;
    GtkWidget* save_button = nullptr;
    GtkWidget* share_button = nullptr;

    GtkWidget* password_entry = nullptr;
    GtkWidget* port_entry = nullptr;
    GtkWidget* target_bitrate_entry = nullptr;
    GtkWidget* windows_monitor_index_entry = nullptr;
    GtkWidget* windows_capture_api_combo_box = nullptr;
    GtkWidget* windows_quality_vs_speed_row = nullptr;
    GtkWidget* windows_quality_vs_speed_scale = nullptr;
    GtkWidget* startx_entry = nullptr;
    GtkWidget* starty_entry = nullptr;
    GtkWidget* endx_entry = nullptr;
    GtkWidget* endx_check_button = nullptr;
    GtkWidget* endy_entry = nullptr;
    GtkWidget* endy_check_button = nullptr;
    GtkWidget* vbv_buf_capacity_entry = nullptr;
    GtkWidget* tcp_upnp_switch = nullptr;
    GtkWidget* sound_forwarding_switch = nullptr;
    GtkWidget* hwencode_switch = nullptr;
    GtkWidget* vapostproc_switch = nullptr;
    GtkWidget* color_downsampling_switch = nullptr;
    GtkWidget* bwe_switch = nullptr;
    GtkWidget* cert_entry = nullptr;
    GtkWidget* key_entry = nullptr;

    bool new_user = false;
    bool dirty = true;

    void show_toast(const std::string& title, unsigned int timeout = 5) {
        AdwToast* toast = adw_toast_new(title.c_str());
        adw_toast_set_timeout(toast, timeout);
        adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
    }

public:
    MainWindow() = default;

    void handle_activate(AdwApplication* app) {
        if (window) {
            if (get_tenebra_pid() == -1) {
                gtk_stack_set_visible_child(GTK_STACK(button_stack), start_button);
            } else {
                gtk_stack_set_visible_child(GTK_STACK(button_stack), running_box);
            }
            gtk_widget_set_visible(window, TRUE);
            return;
        }

        window = adw_application_window_new(GTK_APPLICATION(app));
        gtk_window_set_title(GTK_WINDOW(window), "Tenebra");
        gtk_window_set_default_size(GTK_WINDOW(window), 740, 700);

        GSimpleAction* save_action = g_simple_action_new("save", nullptr);
        glib::connect_signal<GVariant*>(save_action, "activate", [this](GSimpleAction*, GVariant*) {
            save();
        });
        g_action_map_add_action(G_ACTION_MAP(app), G_ACTION(save_action));
        {
#ifdef __APPLE__
            const char* accels[] = {"<Meta>S", nullptr};
#else
            const char* accels[] = {"<Control>S", nullptr};
#endif
            gtk_application_set_accels_for_action(GTK_APPLICATION(app), "app.save", accels);
        }

        GSimpleAction* refresh_action = g_simple_action_new("refresh", nullptr);
        glib::connect_signal<GVariant*>(refresh_action, "activate", [this](GSimpleAction*, GVariant*) {
            refresh(true);
        });
        g_action_map_add_action(G_ACTION_MAP(app), G_ACTION(refresh_action));
        {
#ifdef __APPLE__
            const char* accels[] = {"<Meta>R", nullptr};
#else
            const char* accels[] = {"<Control>R", nullptr};
#endif
            gtk_application_set_accels_for_action(GTK_APPLICATION(app), "app.refresh", accels);
        }

        // The header goes inside an AdwToolbarView rather than being the window's
        // titlebar, so it sits flush with the content and only grows a shadow once
        // something is scrolled under it. Its default style is ADW_TOOLBAR_FLAT
        GtkWidget* toolbar_view = adw_toolbar_view_new();
        adw_application_window_set_content(ADW_APPLICATION_WINDOW(window), toolbar_view);

        GtkWidget* header_bar = adw_header_bar_new();
        adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar_view), header_bar);

        button_stack = gtk_stack_new();
        gtk_stack_set_hhomogeneous(GTK_STACK(button_stack), FALSE);
        adw_header_bar_pack_start(ADW_HEADER_BAR(header_bar), button_stack);

        start_button = gtk_button_new_with_label("Start");
        gtk_widget_add_css_class(start_button, "suggested-action");
        glib::connect_signal(start_button, "clicked", [this](GtkWidget*) {
            if (!start()) {
                gtk_stack_set_visible_child(GTK_STACK(button_stack), running_box);
            }
        });
        gtk_stack_add_child(GTK_STACK(button_stack), start_button);

        running_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_add_css_class(running_box, "linked");
        gtk_stack_add_child(GTK_STACK(button_stack), running_box);

        GtkWidget* stop_button = gtk_button_new_with_label("Stop");
        gtk_widget_add_css_class(stop_button, "destructive-action");
        glib::connect_signal(stop_button, "clicked", [this](GtkWidget*) {
            if (!stop()) {
                gtk_stack_set_visible_child(GTK_STACK(button_stack), start_button);
            }
        });
        gtk_box_append(GTK_BOX(running_box), stop_button);

        GtkWidget* restart_button = gtk_button_new_with_label("Restart");
        glib::connect_signal(restart_button, "clicked", [this](GtkWidget*) {
            if (!stop(false) && !start()) {
                show_toast("Tenebra has been restarted");
            }
        });
        gtk_box_append(GTK_BOX(running_box), restart_button);

        save_button = gtk_button_new_from_icon_name("document-save-symbolic");
        gtk_widget_set_tooltip_text(save_button, "Save");
        glib::connect_signal(save_button, "clicked", [this](GtkWidget*) {
            save(false);
        });
        adw_header_bar_pack_start(ADW_HEADER_BAR(header_bar), save_button);

        GtkWidget* refresh_button = gtk_button_new_from_icon_name("view-refresh-symbolic");
        gtk_widget_set_tooltip_text(refresh_button, "Refresh");
        glib::connect_signal(refresh_button, "clicked", [this](GtkWidget*) {
            refresh(true);
        });
        adw_header_bar_pack_end(ADW_HEADER_BAR(header_bar), refresh_button);

        GtkWidget* share_popover = gtk_popover_new();

        GtkWidget* share_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
        gtk_widget_set_margin_top(share_box, 3);
        gtk_widget_set_margin_bottom(share_box, 3);
        gtk_widget_set_margin_start(share_box, 3);
        gtk_widget_set_margin_end(share_box, 3);
        gtk_box_set_spacing(GTK_BOX(share_box), 6);
        gtk_popover_set_child(GTK_POPOVER(share_popover), share_box);

        GtkWidget* address_entry = gtk_entry_new();
        gtk_entry_set_placeholder_text(GTK_ENTRY(address_entry), "Address");
        // Sized in characters rather than pixels so the popover widens with the font.
        // A fixed pixel width clipped the address once text was scaled past 100%.
        // Don't set max-width-chars here: it sets the natural width, not a cap
        gtk_editable_set_width_chars(GTK_EDITABLE(address_entry), 24);
        glib::connect_signal(address_entry, "map", [this, address_entry](GtkWidget*) {
            gtk_editable_set_text(GTK_EDITABLE(address_entry), (get_common_name_from_cert(gtk_editable_get_text(GTK_EDITABLE(cert_entry))) + ':' + std::to_string((unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(port_entry)))).c_str());
        });
        gtk_box_append(GTK_BOX(share_box), address_entry);

        GtkWidget* view_only_check_button = gtk_check_button_new_with_label("View only");
        gtk_box_append(GTK_BOX(share_box), view_only_check_button);

        GtkWidget* copy_link_button = gtk_button_new_with_label("Copy One-Time Link");
        gtk_widget_add_css_class(copy_link_button, "suggested-action");
        glib::connect_signal(copy_link_button, "clicked", [this, address_entry, view_only_check_button](GtkWidget* copy_link_button) {
            json req_json = {
                {"password", gtk_editable_get_text(GTK_EDITABLE(password_entry))},
                {"view_only", (bool) gtk_check_button_get_active(GTK_CHECK_BUTTON(view_only_check_button))},
            };

            pn::TLSContext tls_context;
            if (pn::Status result = tls_context.init_client(SSL_VERIFY_NONE); !result) {
                show_toast("Failed to create one-time link key: " + result.error().message());
                return;
            }

            pw::Response resp;
            if (pn::Status result = pw::fetch("POST", "https://localhost:" + std::to_string((unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(port_entry))) + "/create_key", resp, req_json.dump(), {{"Content-Type", "application/json"}}, {.tls_context = &tls_context}); !result) {
                show_toast("Failed to create one-time link key: " + result.error().message());
                return;
            } else if (resp.status_code != 200) {
                show_toast("Failed to create one-time link key: Response has status code " + std::to_string(resp.status_code));
                return;
            }

            pw::URLInfo url_info;
            url_info.scheme = "https";
            url_info.host = "audacia.duckdns.org";
            *url_info.query_parameters = {
                {"address", gtk_editable_get_text(GTK_EDITABLE(address_entry))},
                {"key", resp.body_string()},
                {"view_only", gtk_check_button_get_active(GTK_CHECK_BUTTON(view_only_check_button)) ? "true" : "false"},
            };
            gdk_clipboard_set_text(gdk_display_get_clipboard(gtk_widget_get_display(copy_link_button)), url_info.build().c_str());

            show_toast("Copied one-time access link to clipboard");
            gtk_menu_button_popdown(GTK_MENU_BUTTON(share_button));
        });
        gtk_box_append(GTK_BOX(share_box), copy_link_button);

        share_button = gtk_menu_button_new();
        // emblem-shared-symbolic exists in Breeze but not in Adwaita, so on Windows it
        // fell back to Adwaita's 16x16 emblem-shared.png, upscaled and blurry.
        // send-to-symbolic is crisp in both, and renders as the same share glyph under
        // Breeze. Don't swap it for folder-publicshare-symbolic: that one is a share
        // glyph in Adwaita but two people in Breeze
        gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(share_button), "send-to-symbolic");
        gtk_widget_set_tooltip_text(share_button, "Share");
        gtk_menu_button_set_popover(GTK_MENU_BUTTON(share_button), share_popover);
        adw_header_bar_pack_end(ADW_HEADER_BAR(header_bar), share_button);

        toast_overlay = adw_toast_overlay_new();
        adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar_view), toast_overlay);

        // AdwPreferencesPage supplies its own scrolling, clamping and margins
        GtkWidget* page = adw_preferences_page_new();
        adw_toast_overlay_set_child(ADW_TOAST_OVERLAY(toast_overlay), page);

        auto add_group = [page](const char* title) {
            AdwPreferencesGroup* group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
            adw_preferences_group_set_title(group, title);
            adw_preferences_page_add(ADW_PREFERENCES_PAGE(page), group);
            return group;
        };

        // Groups appear in the order they are added to the page, so rows below may be
        // created in whatever order their signal handlers require
        AdwPreferencesGroup* connection_group = add_group("Connection");
        AdwPreferencesGroup* capture_group = add_group("Screen Capture");
        AdwPreferencesGroup* video_group = add_group("Video Encoding");
        AdwPreferencesGroup* audio_group = add_group("Audio");
        AdwPreferencesGroup* network_group = add_group("Network");
        AdwPreferencesGroup* security_group = add_group("Security");
        adw_preferences_group_set_description(security_group, "Both files must be PEM-encoded, and the certificate should include any intermediates");

        password_entry = adw_password_entry_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(password_entry), "Password");
        glib::connect_signal<GParamSpec*>(password_entry, "notify::text", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(connection_group, password_entry);

        port_entry = adw_spin_row_new_with_range(0., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(port_entry), "Port");
        adw_spin_row_set_value(ADW_SPIN_ROW(port_entry), 8080);
        glib::connect_signal<GParamSpec*>(port_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(connection_group, port_entry);

        target_bitrate_entry = adw_spin_row_new_with_range(50., 12000., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(target_bitrate_entry), "Target Bitrate (kbps)");
        adw_spin_row_set_value(ADW_SPIN_ROW(target_bitrate_entry), 4000);
        glib::connect_signal<GParamSpec*>(target_bitrate_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(video_group, target_bitrate_entry);

        windows_monitor_index_entry = adw_spin_row_new_with_range(-1., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(windows_monitor_index_entry), "Monitor Index");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(windows_monitor_index_entry), "The index of the monitor to capture (-1 = primary monitor)");
        adw_spin_row_set_value(ADW_SPIN_ROW(windows_monitor_index_entry), -1.);
        glib::connect_signal<GParamSpec*>(windows_monitor_index_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(capture_group, windows_monitor_index_entry);

        windows_capture_api_combo_box = adw_combo_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(windows_capture_api_combo_box), "Screen Capture API");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(windows_capture_api_combo_box), "The API to use for screen capture (DXGI is more compatible, but WGC is newer and more modern)");
        const char* capture_apis[] = {"DXGI", "WGC", nullptr};
        adw_combo_row_set_model(ADW_COMBO_ROW(windows_capture_api_combo_box), G_LIST_MODEL(gtk_string_list_new(capture_apis)));
        adw_combo_row_set_selected(ADW_COMBO_ROW(windows_capture_api_combo_box), 0);
        glib::connect_signal<GParamSpec*>(windows_capture_api_combo_box, "notify::selected", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(capture_group, windows_capture_api_combo_box);

        startx_entry = adw_spin_row_new_with_range(0., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(startx_entry), "Start X");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(startx_entry), "The x-coordinate to start streaming at");
        glib::connect_signal<GParamSpec*>(startx_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(capture_group, startx_entry);

        starty_entry = adw_spin_row_new_with_range(0., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(starty_entry), "Start Y");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(starty_entry), "The y-coordinate to start streaming at");
        glib::connect_signal<GParamSpec*>(starty_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(capture_group, starty_entry);

        endx_entry = adw_spin_row_new_with_range(0., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(endx_entry), "End X");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(endx_entry), "The x-coordinate to stop streaming at");
        glib::connect_signal<GParamSpec*>(endx_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(capture_group, endx_entry);

        endx_check_button = gtk_check_button_new();
        gtk_widget_set_valign(endx_check_button, GTK_ALIGN_CENTER);
        glib::connect_signal<GParamSpec*>(endx_check_button, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_action_row_add_prefix(ADW_ACTION_ROW(endx_entry), endx_check_button);

        endy_entry = adw_spin_row_new_with_range(0., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(endy_entry), "End Y");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(endy_entry), "The y-coordinate to stop streaming at");
        glib::connect_signal<GParamSpec*>(endy_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(capture_group, endy_entry);

        endy_check_button = gtk_check_button_new();
        gtk_widget_set_valign(endy_check_button, GTK_ALIGN_CENTER);
        glib::connect_signal<GParamSpec*>(endy_check_button, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_action_row_add_prefix(ADW_ACTION_ROW(endy_entry), endy_check_button);

        vbv_buf_capacity_entry = adw_spin_row_new_with_range(1., 1000., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(vbv_buf_capacity_entry), "VBV Buffer Capacity (ms)");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(vbv_buf_capacity_entry), "The size of the video buffering verifier (VBV) buffer, which controls how smoothly bitrate is distributed to prevent playback stuttering or quality drops");
        adw_spin_row_set_value(ADW_SPIN_ROW(vbv_buf_capacity_entry), 120);
        glib::connect_signal<GParamSpec*>(vbv_buf_capacity_entry, "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(video_group, vbv_buf_capacity_entry);

        tcp_upnp_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(tcp_upnp_switch), "Automatic ICE-TCP UPnP Forwarding");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(tcp_upnp_switch), "Automatically forwards TCP ports for ICE-TCP");
        adw_switch_row_set_active(ADW_SWITCH_ROW(tcp_upnp_switch), TRUE);
        glib::connect_signal<GParamSpec*>(tcp_upnp_switch, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(network_group, tcp_upnp_switch);

        sound_forwarding_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(sound_forwarding_switch), "Sound Forwarding");
#ifndef __APPLE__
        adw_switch_row_set_active(ADW_SWITCH_ROW(sound_forwarding_switch), TRUE);
#endif
        glib::connect_signal<GParamSpec*>(sound_forwarding_switch, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(audio_group, sound_forwarding_switch);

        hwencode_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(hwencode_switch), "Hardware-Accelerated Video Encoding");
#ifdef _WIN32
        adw_action_row_set_subtitle(ADW_ACTION_ROW(hwencode_switch), "Uses Microsoft Media Foundation for video encoding and conversion");
#elif defined(__APPLE__)
        adw_action_row_set_subtitle(ADW_ACTION_ROW(hwencode_switch), "Uses Apple VideoToolbox for video encoding and conversion");
#else
        adw_action_row_set_subtitle(ADW_ACTION_ROW(hwencode_switch), "Uses VA-API on devices with Intel or AMD GPUs");
#endif
        glib::connect_signal<GParamSpec*>(hwencode_switch, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        glib::connect_signal<GParamSpec*>(hwencode_switch, "notify::active", [this](GtkWidget* hwencode_switch, GParamSpec*) {
            if (adw_switch_row_get_active(ADW_SWITCH_ROW(hwencode_switch))) {
#ifdef _WIN32
                gtk_widget_set_sensitive(windows_quality_vs_speed_row, TRUE);
#elif defined(__APPLE__)
                gtk_widget_set_sensitive(vbv_buf_capacity_entry, FALSE);
                gtk_widget_set_sensitive(bwe_switch, FALSE);
                adw_switch_row_set_active(ADW_SWITCH_ROW(bwe_switch), FALSE);
#else
                gtk_widget_set_sensitive(vapostproc_switch, TRUE);
#endif
                gtk_widget_set_sensitive(color_downsampling_switch, FALSE);
                adw_switch_row_set_active(ADW_SWITCH_ROW(color_downsampling_switch), TRUE);
            } else {
#ifdef _WIN32
                gtk_widget_set_sensitive(windows_quality_vs_speed_row, FALSE);
#elif defined(__APPLE__)
                gtk_widget_set_sensitive(vbv_buf_capacity_entry, TRUE);
                gtk_widget_set_sensitive(bwe_switch, TRUE);
#else
                gtk_widget_set_sensitive(vapostproc_switch, FALSE);
                adw_switch_row_set_active(ADW_SWITCH_ROW(vapostproc_switch), FALSE);
#endif
                gtk_widget_set_sensitive(color_downsampling_switch, TRUE);
            }
        });
        adw_preferences_group_add(video_group, hwencode_switch);

        // Created after hwencode_switch so that it lands directly beneath the toggle that
        // controls its sensitivity. Safe because nothing activates that toggle until
        // refresh() runs, by which point every row exists
        windows_quality_vs_speed_row = adw_action_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(windows_quality_vs_speed_row), "Quality vs. Speed");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(windows_quality_vs_speed_row), "0 = high speed and low quality, 100 = high quality and low speed");
        gtk_widget_set_sensitive(windows_quality_vs_speed_row, FALSE);
        adw_preferences_group_add(video_group, windows_quality_vs_speed_row);

        windows_quality_vs_speed_scale = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL, 0., 100., 1.);
        gtk_range_set_value(GTK_RANGE(windows_quality_vs_speed_scale), 50.);
        gtk_scale_add_mark(GTK_SCALE(windows_quality_vs_speed_scale), 50., GTK_POS_BOTTOM, nullptr);
        gtk_scale_set_draw_value(GTK_SCALE(windows_quality_vs_speed_scale), TRUE);
        gtk_widget_set_size_request(windows_quality_vs_speed_scale, 150, -1);
        glib::connect_signal<GParamSpec*>(gtk_range_get_adjustment(GTK_RANGE(windows_quality_vs_speed_scale)), "notify::value", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_action_row_add_suffix(ADW_ACTION_ROW(windows_quality_vs_speed_row), windows_quality_vs_speed_scale);

        vapostproc_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(vapostproc_switch), "VA-API Video Conversion");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(vapostproc_switch), "Enables hardware-accelerated video format conversion on devices with Intel or AMD GPUs");
        gtk_widget_set_sensitive(vapostproc_switch, FALSE);
        glib::connect_signal<GParamSpec*>(vapostproc_switch, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(video_group, vapostproc_switch);

        color_downsampling_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(color_downsampling_switch), "Color Channel Downsampling");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(color_downsampling_switch), "Encodes frames in NV12 format");
        adw_switch_row_set_active(ADW_SWITCH_ROW(color_downsampling_switch), TRUE);
        glib::connect_signal<GParamSpec*>(color_downsampling_switch, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(video_group, color_downsampling_switch);

        bwe_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(bwe_switch), "Bandwidth Estimation");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(bwe_switch), "Adjusts media bitrate on the fly to adapt to changing network conditions");
        adw_switch_row_set_active(ADW_SWITCH_ROW(bwe_switch), TRUE);
        glib::connect_signal<GParamSpec*>(bwe_switch, "notify::active", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(network_group, bwe_switch);

        cert_entry = adw_entry_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(cert_entry), "TLS Certificate");
        glib::connect_signal<GParamSpec*>(cert_entry, "notify::text", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(security_group, cert_entry);

        GtkWidget* choose_cert_button = gtk_button_new_from_icon_name("document-open-symbolic");
        gtk_widget_set_tooltip_text(choose_cert_button, "Choose File");
        gtk_widget_set_valign(choose_cert_button, GTK_ALIGN_CENTER);
        gtk_widget_add_css_class(choose_cert_button, "flat");
        glib::connect_signal(choose_cert_button, "clicked", std::bind(&MainWindow::handle_choose_file, this, std::placeholders::_1, cert_entry));
        adw_entry_row_add_suffix(ADW_ENTRY_ROW(cert_entry), choose_cert_button);

        key_entry = adw_entry_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(key_entry), "Private Key");
        glib::connect_signal<GParamSpec*>(key_entry, "notify::text", std::bind(&MainWindow::handle_change, this, std::placeholders::_1, std::placeholders::_2));
        adw_preferences_group_add(security_group, key_entry);

        GtkWidget* choose_key_button = gtk_button_new_from_icon_name("document-open-symbolic");
        gtk_widget_set_tooltip_text(choose_key_button, "Choose File");
        gtk_widget_set_valign(choose_key_button, GTK_ALIGN_CENTER);
        gtk_widget_add_css_class(choose_key_button, "flat");
        glib::connect_signal(choose_key_button, "clicked", std::bind(&MainWindow::handle_choose_file, this, std::placeholders::_1, key_entry));
        adw_entry_row_add_suffix(ADW_ENTRY_ROW(key_entry), choose_key_button);

#ifdef _WIN32
        gtk_widget_set_visible(vapostproc_switch, FALSE);
#elif defined(__APPLE__)
        gtk_widget_set_visible(windows_monitor_index_entry, FALSE);
        gtk_widget_set_visible(windows_capture_api_combo_box, FALSE);
        gtk_widget_set_visible(windows_quality_vs_speed_row, FALSE);
        gtk_widget_set_visible(sound_forwarding_switch, FALSE);
        gtk_widget_set_visible(GTK_WIDGET(audio_group), FALSE); // Otherwise its title would sit above nothing
        gtk_widget_set_visible(vapostproc_switch, FALSE);
#else
        gtk_widget_set_visible(windows_monitor_index_entry, FALSE);
        gtk_widget_set_visible(windows_capture_api_combo_box, FALSE);
        gtk_widget_set_visible(windows_quality_vs_speed_row, FALSE);
#endif

        refresh();
        g_timeout_add(2000, [](void* data) -> gboolean {
            auto tenebra = (MainWindow*) data;
            if (gtk_widget_is_visible(tenebra->window)) {
                if (get_tenebra_pid() == -1) {
                    gtk_stack_set_visible_child(GTK_STACK(tenebra->button_stack), tenebra->start_button);
                } else {
                    gtk_stack_set_visible_child(GTK_STACK(tenebra->button_stack), tenebra->running_box);
                }
            }
            return TRUE;
        },
            this);

        glib::connect_signal(window, "close-request", [this](GtkWidget* window) -> gboolean {
            if (dirty) {
                AdwDialog* dialog = adw_alert_dialog_new("Save Changes?", "You have unsaved changes. Changes that are not saved will be permanently lost.");
                adw_alert_dialog_add_responses(ADW_ALERT_DIALOG(dialog), "cancel", "Cancel", "discard", "Discard", "save", "Save", nullptr);
                adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dialog), "discard", ADW_RESPONSE_DESTRUCTIVE);
                adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dialog), "save", ADW_RESPONSE_SUGGESTED);
                adw_alert_dialog_set_default_response(ADW_ALERT_DIALOG(dialog), "save");
                adw_alert_dialog_set_close_response(ADW_ALERT_DIALOG(dialog), "cancel");
                glib::connect_signal<char*>(dialog, "response", [this, window](AdwDialog*, char* response) {
                    if (!strcmp(response, "save")) {
                        if (!save(false)) gtk_widget_set_visible(window, FALSE);
                    } else if (!strcmp(response, "discard")) {
                        refresh();
                        gtk_widget_set_visible(window, FALSE);
                    }
                });
                adw_dialog_present(dialog, window);
            } else {
                gtk_widget_set_visible(window, FALSE);
            }
            return TRUE;
        });

        gtk_window_present(GTK_WINDOW(window));
        if (new_user) {
            AdwDialog* dialog = adw_alert_dialog_new("Welcome!", "Welcome to Tenebra! Here, you can configure Tenebra's settings. Before starting, make sure you’ve set a password and directed it to your TLS certificate.");
            adw_alert_dialog_add_responses(ADW_ALERT_DIALOG(dialog), "thanks", "Thanks!", nullptr);
            adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dialog), "thanks", ADW_RESPONSE_SUGGESTED);
            adw_alert_dialog_set_default_response(ADW_ALERT_DIALOG(dialog), "thanks");
            adw_dialog_present(dialog, window);
        }
    }

    void handle_change(void*, GParamSpec*) {
        gtk_widget_set_sensitive(save_button, dirty = true);
    }

    void handle_choose_file(GtkWidget*, GtkWidget* entry) {
        glib::Object<GtkFileFilter> pem_filter = gtk_file_filter_new();
        gtk_file_filter_add_suffix(pem_filter.get(), "pem");
        gtk_file_filter_set_name(pem_filter.get(), "Privacy-Enhanced Mail Files");

        glib::Object<GListStore> filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
        g_list_store_append(filters.get(), pem_filter.get());

        GtkFileDialog* file_dialog = gtk_file_dialog_new();
        gtk_file_dialog_set_filters(file_dialog, G_LIST_MODEL(filters.get()));
        gtk_file_dialog_open(file_dialog, GTK_WINDOW(window), nullptr, (GAsyncReadyCallback) + [](GtkFileDialog* file_dialog, GAsyncResult* result, void* data) {
            if (glib::Object<GFile> file = gtk_file_dialog_open_finish(file_dialog, result, nullptr)) {
                gtk_editable_set_text(GTK_EDITABLE(data), g_file_get_path(file.get()));
            }
        },
            entry);
    }

    void refresh(bool show_confirmation_dialog = false) {
        if (show_confirmation_dialog && dirty) {
            AdwDialog* dialog = adw_alert_dialog_new("Save Changes?", "You have unsaved changes. Changes that are not saved will be permanently lost.");
            adw_alert_dialog_add_responses(ADW_ALERT_DIALOG(dialog), "cancel", "Cancel", "discard", "Discard", "save", "Save", nullptr);
            adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dialog), "discard", ADW_RESPONSE_DESTRUCTIVE);
            adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dialog), "save", ADW_RESPONSE_SUGGESTED);
            adw_alert_dialog_set_default_response(ADW_ALERT_DIALOG(dialog), "save");
            adw_alert_dialog_set_close_response(ADW_ALERT_DIALOG(dialog), "cancel");
            glib::connect_signal<char*>(dialog, "response", [this](AdwDialog*, char* response) {
                if (!strcmp(response, "save")) {
                    save();

                    if (get_tenebra_pid() == -1) {
                        gtk_stack_set_visible_child(GTK_STACK(button_stack), start_button);
                    } else {
                        gtk_stack_set_visible_child(GTK_STACK(button_stack), running_box);
                    }
                } else if (!strcmp(response, "discard")) {
                    refresh();
                }
            });
            adw_dialog_present(dialog, window);
            return;
        }

        if (get_tenebra_pid() == -1) {
            gtk_stack_set_visible_child(GTK_STACK(button_stack), start_button);
        } else {
            gtk_stack_set_visible_child(GTK_STACK(button_stack), running_box);
        }

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

                gtk_editable_set_text(GTK_EDITABLE(password_entry), password.c_str());
                adw_spin_row_set_value(ADW_SPIN_ROW(port_entry), port);
                adw_spin_row_set_value(ADW_SPIN_ROW(target_bitrate_entry), target_bitrate);
                adw_spin_row_set_value(ADW_SPIN_ROW(windows_monitor_index_entry), windows_monitor_index);
                adw_combo_row_set_selected(ADW_COMBO_ROW(windows_capture_api_combo_box), windows_capture_api == "wgc" ? 1 : 0);
                gtk_range_set_value(GTK_RANGE(windows_quality_vs_speed_scale), windows_quality_vs_speed);
                adw_spin_row_set_value(ADW_SPIN_ROW(startx_entry), startx);
                adw_spin_row_set_value(ADW_SPIN_ROW(starty_entry), starty);
                adw_spin_row_set_value(ADW_SPIN_ROW(vbv_buf_capacity_entry), vbv_buf_capacity);
                adw_switch_row_set_active(ADW_SWITCH_ROW(tcp_upnp_switch), tcp_upnp);
                adw_switch_row_set_active(ADW_SWITCH_ROW(sound_forwarding_switch), sound_forwarding);
                adw_switch_row_set_active(ADW_SWITCH_ROW(hwencode_switch), hwencode);
                adw_switch_row_set_active(ADW_SWITCH_ROW(vapostproc_switch), vapostproc);
                adw_switch_row_set_active(ADW_SWITCH_ROW(color_downsampling_switch), !full_chroma);
                adw_switch_row_set_active(ADW_SWITCH_ROW(bwe_switch), !no_bwe);
                gtk_editable_set_text(GTK_EDITABLE(cert_entry), cert.c_str());
                gtk_editable_set_text(GTK_EDITABLE(key_entry), key.c_str());

                if (config.contains("endx")) {
                    adw_spin_row_set_value(ADW_SPIN_ROW(endx_entry), toml::find<unsigned short>(config, "endx"));
                    gtk_check_button_set_active(GTK_CHECK_BUTTON(endx_check_button), TRUE);
                } else {
                    gtk_check_button_set_active(GTK_CHECK_BUTTON(endx_check_button), FALSE);
                }

                if (config.contains("endy")) {
                    adw_spin_row_set_value(ADW_SPIN_ROW(endy_entry), toml::find<unsigned short>(config, "endy"));
                    gtk_check_button_set_active(GTK_CHECK_BUTTON(endy_check_button), TRUE);
                } else {
                    gtk_check_button_set_active(GTK_CHECK_BUTTON(endy_check_button), FALSE);
                }

                gtk_widget_set_sensitive(save_button, dirty = false);
            } catch (...) {
                show_toast("Failed to parse existing settings at " + (config_path / "config.toml").string());
            }
        }
    }

    int start() {
        if (save(false) == -1) return -1;

#ifdef _WIN32
        SC_HANDLE sc_manager;
        if (!(sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT))) {
            show_toast("Failed to start Tenebra (OpenSCManager failed, error " + std::to_string(GetLastError()) + ')');
            return -1;
        }

        SC_HANDLE service;
        if (!(service = OpenService(sc_manager, "Tenebra", SERVICE_START))) {
            show_toast("Failed to start Tenebra (OpenSCManager failed, error " + std::to_string(GetLastError()) + ')');
            CloseServiceHandle(sc_manager);
            return -1;
        }

        if (!StartService(service, 0, nullptr)) {
            show_toast("Failed to start Tenebra (StartService failed, error " + std::to_string(GetLastError()) + ')');
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return -1;
        }

        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
#else
        int pipe_fds[2];
        if (pipe(pipe_fds) == -1) {
            show_toast("Failed to start Tenebra (pipe failed, error " + std::to_string(errno) + ')');
            return -1;
        }

        if (pid_t pid = fork(); pid == -1) {
            show_toast("Failed to start Tenebra (fork failed, error " + std::to_string(errno) + ')');
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
            show_toast("Failed to start Tenebra (error " + std::to_string(error) + ')');
            close(pipe_fds[0]);
            return -1;
        }

        close(pipe_fds[0]);
#endif
        return 0;
    }

    int stop(bool show_not_running_toast = true) {
        if (pid_t pid = get_tenebra_pid(); pid != -1) {
#ifdef _WIN32
            HANDLE process;
            if ((process = OpenProcess(PROCESS_TERMINATE, FALSE, pid)) == nullptr) {
                show_toast("Failed to stop Tenebra (OpenProcess failed, error " + std::to_string(GetLastError()) + ')');
                return -1;
            }
            if (!TerminateProcess(process, 1)) {
                show_toast("Failed to stop Tenebra (TerminateProcess failed, error " + std::to_string(GetLastError()) + ')');
                CloseHandle(process);
                return -1;
            }
            CloseHandle(process);
#else
            if (kill(pid, SIGTERM) == -1) {
                show_toast("Failed to stop Tenebra (kill failed, error " + std::to_string(errno) + ')');
                return -1;
            }

            // Wait for Tenebra to die
            for (;; std::this_thread::sleep_for(std::chrono::milliseconds(10))) {
                if (kill(pid, 0) == -1 && errno == ESRCH) {
                    break;
                }
            }
#endif
        } else if (show_not_running_toast) {
            show_toast("Tenebra wasn't running in the first place 🫤");
        }
        return 0;
    }

    int save(bool show_success_toast = true) {
        auto config_path = get_config_path();
        if (!config_path.empty()) {
            if (!std::filesystem::exists(config_path)) {
                std::filesystem::create_directory(config_path);
            }

            std::ofstream config_file(config_path / "config.toml");
            if (config_file.is_open()) {
                toml::value config({
                    {"password", gtk_editable_get_text(GTK_EDITABLE(password_entry))},
                    {"port", (unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(port_entry))},
                    {"target_bitrate", (unsigned int) adw_spin_row_get_value(ADW_SPIN_ROW(target_bitrate_entry))},
                    {"windows_monitor_index", (int) adw_spin_row_get_value(ADW_SPIN_ROW(windows_monitor_index_entry))},
                    {"windows_capture_api", pw::string::to_lower_copy(gtk_string_list_get_string(GTK_STRING_LIST(adw_combo_row_get_model(ADW_COMBO_ROW(windows_capture_api_combo_box))), adw_combo_row_get_selected(ADW_COMBO_ROW(windows_capture_api_combo_box))))},
                    {"windows_quality_vs_speed", (unsigned short) gtk_range_get_value(GTK_RANGE(windows_quality_vs_speed_scale))},
                    {"startx", (unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(startx_entry))},
                    {"starty", (unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(starty_entry))},
                    {"vbv_buf_capacity", (unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(vbv_buf_capacity_entry))},
                    {"tcp_upnp", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(tcp_upnp_switch))},
                    {"sound_forwarding", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(sound_forwarding_switch))},
                    {"hwencode", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(hwencode_switch))},
                    {"vapostproc", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(vapostproc_switch))},
                    {"full_chroma", !adw_switch_row_get_active(ADW_SWITCH_ROW(color_downsampling_switch))},
                    {"no_bwe", !adw_switch_row_get_active(ADW_SWITCH_ROW(bwe_switch))},
                    {"cert", gtk_editable_get_text(GTK_EDITABLE(cert_entry))},
                    {"key", gtk_editable_get_text(GTK_EDITABLE(key_entry))},
                });
                if (gtk_check_button_get_active(GTK_CHECK_BUTTON(endx_check_button))) {
                    config["endx"] = (unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(endx_entry));
                }
                if (gtk_check_button_get_active(GTK_CHECK_BUTTON(endy_check_button))) {
                    config["endy"] = (unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(endy_entry));
                }

                if (config_file << config << std::flush) {
                    gtk_widget_set_sensitive(save_button, dirty = false);
                    if (show_success_toast) {
                        show_toast("Settings saved to " + (config_path / "config.toml").string());
                    }
                    return 0;
                }
            }
        }

        show_toast("Failed to save settings to " + (config_path / "config.toml").string());
        return -1;
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
            SetProcessDpiAwareness(PROCESS_SYSTEM_DPI_AWARE);
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

    MainWindow window;
    glib::Object<AdwApplication> app = adw_application_new("org.telewindow.Tenebra", G_APPLICATION_DEFAULT_FLAGS);
    app.connect_signal("activate", std::bind(&MainWindow::handle_activate, &window, std::placeholders::_1));
    int ret = g_application_run(G_APPLICATION(app.get()), argc, argv);

    (void) pn::quit();
    return ret;
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    return main(__argc, __argv);
}
#endif
