#include <gtk/gtk.h>
#include <stdio.h>

static void on_button_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkLabel *label = GTK_LABEL(user_data);
    gtk_label_set_text(label, "GTK button clicked");
    g_print("G11GTK: button clicked -- G11 INPUT\n");
    fflush(stdout);
}

static void create_window(void) {
    g_print("G11GTK: create window -- G11 GTK\n");
    fflush(stdout);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Epin Toolkit Demo");
    gtk_window_set_default_size(GTK_WINDOW(window), 560, 360);
    gtk_window_set_icon_name(GTK_WINDOW(window), "terminal");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_set_margin_top(box, 24);
    gtk_widget_set_margin_bottom(box, 24);
    gtk_widget_set_margin_start(box, 28);
    gtk_widget_set_margin_end(box, 28);
    gtk_container_add(GTK_CONTAINER(window), box);

    GtkWidget *image = gtk_image_new_from_icon_name("terminal", GTK_ICON_SIZE_DIALOG);
    gtk_widget_set_halign(image, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), image, FALSE, FALSE, 0);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<b>GTK toolkit rendering</b>");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0);

    GtkWidget *body = gtk_label_new("Pango text, a theme icon, a button, and an editable entry are rendered by GTK into wl_shm.");
    gtk_label_set_line_wrap(GTK_LABEL(body), TRUE);
    gtk_label_set_xalign(GTK_LABEL(body), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), body, FALSE, FALSE, 0);

    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), "editable GTK entry");
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 0);

    GtkWidget *button = gtk_button_new_with_label("Update label");
    gtk_widget_set_halign(button, GTK_ALIGN_START);
    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), body);
    gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 0);

    gtk_widget_show_all(window);
    g_print("G11GTK: window shown -- G11 COMMIT\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    g_setenv("GDK_BACKEND", "wayland", FALSE);
    g_print("G11GTK: starting -- G11 START\n");
    fflush(stdout);

    gtk_init(&argc, &argv);
    create_window();
    gtk_main();
    g_print("G11GTK: exit status=0\n");
    fflush(stdout);
    return 0;
}
