#include "glib.hpp"
#include "toml.hpp"
#include <adwaita.h>
#include <algorithm>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

pid_t get_tenebra_pid() {
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (entry.is_directory()) {
            std::string filename = entry.path().filename();
            if (std::all_of(filename.begin(), filename.end(), isdigit)) {
                std::ifstream comm_file(entry.path() / "comm");
                if (comm_file.is_open()) {
                    std::string comm;
                    if (std::getline(comm_file, comm) && comm == "tenebra") {
                        return std::stoi(filename);
                    }
                }
            }
        }
    }
    return -1;
}

std::filesystem::path get_config_path() {
    std::string ret;
    if (char* config = getenv("XDG_CONFIG_HOME")) {
        ret = std::filesystem::path(config) / "tenebra";
    } else if (char* home = getenv("HOME")) {
        ret = std::filesystem::path(home) / ".config" / "tenebra";
    }
    return ret;
}

class Tenebra {
protected:
    GtkWidget* window;
    GtkWidget* toast_overlay;
    GtkWidget* manage_button;
    GtkWidget* password_entry;
    GtkWidget* port_entry;
    GtkWidget* target_bitrate_entry;
    GtkWidget* startx_entry;
    GtkWidget* tcp_upnp_switch;
    GtkWidget* sound_forwarding_switch;
    GtkWidget* vaapi_switch;
    GtkWidget* vapostproc_switch;
    GtkWidget* fullchroma_switch;
    GtkWidget* bwe_switch;
    GtkWidget* cert_entry;
    GtkWidget* key_entry;

    gulong current_management_signal_handler = 0;

public:
    Tenebra() = default;

    void handle_activate(AdwApplication* app) {
        window = gtk_application_window_new(GTK_APPLICATION(app));
        gtk_window_set_title(GTK_WINDOW(window), "Tenebra");
        gtk_window_set_default_size(GTK_WINDOW(window), 675, 575);

        GSimpleAction* save_action = g_simple_action_new("save", nullptr);
        glib::connect_signal<GVariant*>(save_action, "activate", [this](GSimpleAction*, GVariant*) {
            save();
        });
        g_action_map_add_action(G_ACTION_MAP(app), G_ACTION(save_action));
        gtk_application_set_accels_for_action(GTK_APPLICATION(app), "app.save", (const char*[]) {"<Ctrl>S", nullptr});

        GSimpleAction* refresh_action = g_simple_action_new("refresh", nullptr);
        glib::connect_signal<GVariant*>(refresh_action, "activate", [this](GSimpleAction*, GVariant*) {
            refresh();
        });
        g_action_map_add_action(G_ACTION_MAP(app), G_ACTION(refresh_action));
        gtk_application_set_accels_for_action(GTK_APPLICATION(app), "app.refresh", (const char*[]) {"<Ctrl>R", nullptr});

        GtkWidget* header_bar = adw_header_bar_new();
        gtk_window_set_titlebar(GTK_WINDOW(window), header_bar);

        manage_button = gtk_button_new_with_label("Start");
        gtk_widget_add_css_class(manage_button, "suggested-action");
        adw_header_bar_pack_start(ADW_HEADER_BAR(header_bar), manage_button);

        GtkWidget* save_button = gtk_button_new_from_icon_name("document-save-symbolic");
        glib::connect_signal(save_button, "clicked", [this](GtkWidget*) {
            save();
        });
        adw_header_bar_pack_start(ADW_HEADER_BAR(header_bar), save_button);

        GtkWidget* refresh_button = gtk_button_new_from_icon_name("view-refresh-symbolic");
        glib::connect_signal(refresh_button, "clicked", [this](GtkWidget*) {
            refresh();
        });
        adw_header_bar_pack_end(ADW_HEADER_BAR(header_bar), refresh_button);

        toast_overlay = adw_toast_overlay_new();

        GtkWidget* scrolled_window = gtk_scrolled_window_new();
        adw_toast_overlay_set_child(ADW_TOAST_OVERLAY(toast_overlay), scrolled_window);

        GtkWidget* viewport = gtk_viewport_new(
            gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(scrolled_window)),
            gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scrolled_window)));
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), viewport);

        GtkWidget* clamp = adw_clamp_new();
        adw_clamp_set_unit(ADW_CLAMP(clamp), ADW_LENGTH_UNIT_PX);
        adw_clamp_set_maximum_size(ADW_CLAMP(clamp), 600);
        gtk_viewport_set_child(GTK_VIEWPORT(viewport), clamp);

        GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
        gtk_widget_set_margin_top(box, 24);
        gtk_widget_set_margin_bottom(box, 24);
        gtk_widget_set_margin_start(box, 12);
        gtk_widget_set_margin_end(box, 12);
        adw_clamp_set_child(ADW_CLAMP(clamp), box);

        GtkWidget* list_box = gtk_list_box_new();
        gtk_list_box_set_selection_mode(GTK_LIST_BOX(list_box), GTK_SELECTION_NONE);
        gtk_widget_add_css_class(list_box, "boxed-list");
        gtk_box_append(GTK_BOX(box), list_box);

        password_entry = adw_password_entry_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(password_entry), "Password");
        gtk_list_box_insert(GTK_LIST_BOX(list_box), password_entry, -1);

        port_entry = adw_spin_row_new_with_range(0., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(port_entry), "Port");
        adw_spin_row_set_value(ADW_SPIN_ROW(port_entry), 8080);
        gtk_list_box_insert(GTK_LIST_BOX(list_box), port_entry, -1);

        target_bitrate_entry = adw_spin_row_new_with_range(50., 12000., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(target_bitrate_entry), "Target bitrate");
        adw_spin_row_set_value(ADW_SPIN_ROW(target_bitrate_entry), 4000);
        gtk_list_box_insert(GTK_LIST_BOX(list_box), target_bitrate_entry, -1);

        startx_entry = adw_spin_row_new_with_range(0., 65535., 1.);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(startx_entry), "Start x");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(startx_entry), "The x-coordinate to stream at");
        gtk_list_box_insert(GTK_LIST_BOX(list_box), startx_entry, -1);

        tcp_upnp_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(tcp_upnp_switch), "TCP UPnP");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(tcp_upnp_switch), "Automatically port forwards TCP ports for ICE-TCP");
        adw_switch_row_set_active(ADW_SWITCH_ROW(tcp_upnp_switch), TRUE);
        gtk_list_box_insert(GTK_LIST_BOX(list_box), tcp_upnp_switch, -1);

        sound_forwarding_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(sound_forwarding_switch), "Sound forwarding");
        adw_switch_row_set_active(ADW_SWITCH_ROW(sound_forwarding_switch), TRUE);
        gtk_list_box_insert(GTK_LIST_BOX(list_box), sound_forwarding_switch, -1);

        vaapi_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(vaapi_switch), "VA-API");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(vaapi_switch), "Enables hardware accelerated video encoding on devices with Intel or AMD GPUs");
        glib::connect_signal<GParamSpec*>(vaapi_switch, "notify::active", [this](GtkWidget* vaapi_switch, GParamSpec*) {
            if (adw_switch_row_get_active(ADW_SWITCH_ROW(vaapi_switch))) {
                gtk_widget_set_sensitive(vapostproc_switch, TRUE);
                gtk_widget_set_sensitive(fullchroma_switch, FALSE);
                adw_switch_row_set_active(ADW_SWITCH_ROW(fullchroma_switch), FALSE);
                gtk_widget_set_sensitive(bwe_switch, FALSE);
                adw_switch_row_set_active(ADW_SWITCH_ROW(bwe_switch), FALSE);
            } else {
                gtk_widget_set_sensitive(vapostproc_switch, FALSE);
                adw_switch_row_set_active(ADW_SWITCH_ROW(vapostproc_switch), FALSE);
                gtk_widget_set_sensitive(fullchroma_switch, TRUE);
                gtk_widget_set_sensitive(bwe_switch, TRUE);
            }
        });
        gtk_list_box_insert(GTK_LIST_BOX(list_box), vaapi_switch, -1);

        vapostproc_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(vapostproc_switch), "VA-API video conversion");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(vapostproc_switch), "Enables hardware accelerated video format conversion on devices with Intel or AMD GPUs");
        gtk_widget_set_sensitive(vapostproc_switch, FALSE);
        gtk_list_box_insert(GTK_LIST_BOX(list_box), vapostproc_switch, -1);

        fullchroma_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(fullchroma_switch), "FullChroma™");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(fullchroma_switch), "Improves color fidelity at the cost of performance");
        gtk_list_box_insert(GTK_LIST_BOX(list_box), fullchroma_switch, -1);

        bwe_switch = adw_switch_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(bwe_switch), "Bandwidth estimation");
        adw_action_row_set_subtitle(ADW_ACTION_ROW(bwe_switch), "Adjusts media bitrate on the fly to adapt to changing network conditions");
        adw_switch_row_set_active(ADW_SWITCH_ROW(bwe_switch), TRUE);
        gtk_list_box_insert(GTK_LIST_BOX(list_box), bwe_switch, -1);

        cert_entry = adw_entry_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(cert_entry), "Certificate chain file");
        gtk_list_box_insert(GTK_LIST_BOX(list_box), cert_entry, -1);

        GtkWidget* choose_cert_button = gtk_button_new_from_icon_name("document-open-symbolic");
        gtk_widget_set_valign(choose_cert_button, GTK_ALIGN_CENTER);
        glib::connect_signal<GtkWidget*>(choose_cert_button, "clicked", std::bind(&Tenebra::handle_choose_file, this, std::placeholders::_1, cert_entry));
        adw_entry_row_add_suffix(ADW_ENTRY_ROW(cert_entry), choose_cert_button);

        key_entry = adw_entry_row_new();
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(key_entry), "Private key file");
        gtk_list_box_insert(GTK_LIST_BOX(list_box), key_entry, -1);

        GtkWidget* choose_key_button = gtk_button_new_from_icon_name("document-open-symbolic");
        gtk_widget_set_valign(choose_key_button, GTK_ALIGN_CENTER);
        glib::connect_signal<GtkWidget*>(choose_key_button, "clicked", std::bind(&Tenebra::handle_choose_file, this, std::placeholders::_1, key_entry));
        adw_entry_row_add_suffix(ADW_ENTRY_ROW(key_entry), choose_key_button);

        refresh();

        gtk_window_set_child(GTK_WINDOW(window), toast_overlay);
        gtk_window_present(GTK_WINDOW(window));
    }

    void handle_choose_file(GtkWidget* button, GtkWidget* entry) {
        glib::Object<GtkFileFilter> pem_filter = gtk_file_filter_new();
        gtk_file_filter_add_suffix(pem_filter.get(), "pem");
        gtk_file_filter_set_name(pem_filter.get(), "Privacy-Enhanced Mail Files");

        glib::Object<GListStore> filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
        g_list_store_append(filters.get(), pem_filter.get());

        GtkFileDialog* file_dialog = gtk_file_dialog_new();
        gtk_file_dialog_set_filters(file_dialog, G_LIST_MODEL(filters.get()));
        gtk_file_dialog_open(file_dialog, GTK_WINDOW(window), nullptr, (GAsyncReadyCallback) + [](GtkFileDialog* file_dialog, GAsyncResult* result, gpointer data) {
            if (glib::Object<GFile> file = gtk_file_dialog_open_finish(file_dialog, result, nullptr)) {
                gtk_editable_set_text(GTK_EDITABLE(data), g_file_get_path(file.get()));
            }
        },
            entry);
    }

    void refresh() {
        auto config_path = get_config_path();
        if (!config_path.empty()) {
            try {
                auto config = toml::parse(config_path / "config.toml");
                auto password = toml::find<std::string>(config, "password");
                auto port = toml::find<unsigned short>(config, "port");
                auto target_bitrate = toml::find<unsigned int>(config, "target_bitrate");
                auto startx = toml::find<unsigned short>(config, "startx");
                auto tcp_upnp = toml::find<bool>(config, "tcp_upnp");
                auto sound_forwarding = toml::find<bool>(config, "sound_forwarding");
                auto vaapi = toml::find<bool>(config, "vaapi");
                auto vapostproc = toml::find<bool>(config, "vapostproc");
                auto full_chroma = toml::find<bool>(config, "full_chroma");
                auto no_bwe = toml::find<bool>(config, "no_bwe");
                auto cert = toml::find<std::string>(config, "cert");
                auto key = toml::find<std::string>(config, "key");

                gtk_editable_set_text(GTK_EDITABLE(password_entry), password.c_str());
                adw_spin_row_set_value(ADW_SPIN_ROW(port_entry), port);
                adw_spin_row_set_value(ADW_SPIN_ROW(target_bitrate_entry), target_bitrate);
                adw_spin_row_set_value(ADW_SPIN_ROW(startx_entry), startx);
                adw_switch_row_set_active(ADW_SWITCH_ROW(tcp_upnp_switch), tcp_upnp);
                adw_switch_row_set_active(ADW_SWITCH_ROW(sound_forwarding_switch), sound_forwarding);
                adw_switch_row_set_active(ADW_SWITCH_ROW(vaapi_switch), vaapi);
                adw_switch_row_set_active(ADW_SWITCH_ROW(vapostproc_switch), vapostproc);
                adw_switch_row_set_active(ADW_SWITCH_ROW(fullchroma_switch), full_chroma);
                adw_switch_row_set_active(ADW_SWITCH_ROW(bwe_switch), !no_bwe);
                gtk_editable_set_text(GTK_EDITABLE(cert_entry), cert.c_str());
                gtk_editable_set_text(GTK_EDITABLE(key_entry), key.c_str());
            } catch (const std::exception& e) {
                AdwToast* toast = adw_toast_new(("Failed to parse existing configuration at " + std::string(config_path / "config.toml")).c_str());
                adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
            }
        }

        refresh_management();
    }

    void refresh_management() {
        if (get_tenebra_pid() == -1) {
            gtk_button_set_label(GTK_BUTTON(manage_button), "Start");
            gtk_widget_remove_css_class(manage_button, "destructive-action");
            gtk_widget_add_css_class(manage_button, "suggested-action");

            if (current_management_signal_handler) {
                g_signal_handler_disconnect(manage_button, current_management_signal_handler);
            }
            current_management_signal_handler = glib::connect_signal(manage_button, "clicked", [this](GtkWidget*) {
                if (save(false) == -1) return;

                int pipe_fds[2];
                if (pipe(pipe_fds) == -1) {
                    AdwToast* toast = adw_toast_new("Failed to start Tenebra (pipe creation failed)");
                    adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
                    return;
                }

                pid_t pid;
                if ((pid = fork()) == -1) {
                    AdwToast* toast = adw_toast_new("Failed to start Tenebra (fork failed)");
                    adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
                    close(pipe_fds[0]);
                    close(pipe_fds[1]);
                    return;
                } else if (!pid) {
                    close(pipe_fds[0]); // Close unused read end
                    fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

                    int null_file;
                    if ((null_file = open("/dev/null", O_RDWR)) == -1) {
                        int error = errno;
                        write(pipe_fds[1], &error, sizeof(int));
                        close(pipe_fds[1]);
                        exit(EXIT_FAILURE);
                    }
                    dup2(null_file, STDOUT_FILENO);
                    dup2(null_file, STDERR_FILENO);
                    dup2(null_file, STDIN_FILENO);
                    close(null_file);

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
                    AdwToast* toast = adw_toast_new(("Failed to start Tenebra (error " + std::to_string(error) + ')').c_str());
                    adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
                }

                close(pipe_fds[0]);

                refresh_management();
            });
        } else {
            gtk_button_set_label(GTK_BUTTON(manage_button), "Stop");
            gtk_widget_remove_css_class(manage_button, "suggested-action");
            gtk_widget_add_css_class(manage_button, "destructive-action");

            if (current_management_signal_handler) {
                g_signal_handler_disconnect(manage_button, current_management_signal_handler);
            }
            current_management_signal_handler = glib::connect_signal(manage_button, "clicked", [this](GtkWidget*) {
                pid_t tenebra_pid;
                if ((tenebra_pid = get_tenebra_pid()) != -1) {
                    if (kill(tenebra_pid, SIGTERM) == -1) {
                        AdwToast* toast = adw_toast_new(("Failed to stop Tenebra (error " + std::to_string(errno) + ')').c_str());
                        adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
                    }

                    int status;
                    wait(&status);
                    AdwToast* toast = adw_toast_new(("Tenebra exited with status code " + std::to_string(status)).c_str());
                    adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
                } else {
                    AdwToast* toast = adw_toast_new("Tenebra is already stopped!");
                    adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
                }
                refresh_management();
            });
        }
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
                    {"startx", (unsigned short) adw_spin_row_get_value(ADW_SPIN_ROW(startx_entry))},
                    {"tcp_upnp", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(tcp_upnp_switch))},
                    {"sound_forwarding", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(sound_forwarding_switch))},
                    {"vaapi", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(vaapi_switch))},
                    {"vapostproc", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(vapostproc_switch))},
                    {"full_chroma", (bool) adw_switch_row_get_active(ADW_SWITCH_ROW(fullchroma_switch))},
                    {"no_bwe", !adw_switch_row_get_active(ADW_SWITCH_ROW(bwe_switch))},
                    {"cert", gtk_editable_get_text(GTK_EDITABLE(cert_entry))},
                    {"key", gtk_editable_get_text(GTK_EDITABLE(key_entry))},
                });
                config_file << config << std::flush;

                if (show_success_toast) {
                    AdwToast* toast = adw_toast_new(("Configuration written to " + std::string(config_path / "config.toml")).c_str());
                    adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
                }
                return 0;
            }
        }

        AdwToast* toast = adw_toast_new(("Failed to open configuration at " + std::string(config_path / "config.toml")).c_str());
        adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toast_overlay), toast);
        return -1;
    }
};

int main(int argc, char* argv[]) {
    glib::Object<AdwApplication> app = adw_application_new("org.telewindow.Tenebra", G_APPLICATION_DEFAULT_FLAGS);

    Tenebra tenebra;
    app.connect_signal("activate", std::bind(&Tenebra::handle_activate, &tenebra, std::placeholders::_1));

    return g_application_run(G_APPLICATION(app.get()), argc, argv);
}
