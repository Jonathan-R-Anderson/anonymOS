#include <gtk/gtk.h>
static void activate(GtkApplication *app, gpointer d) {
    GtkWidget *w = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(w), "HanonymOS");
    gtk_window_set_default_size(GTK_WINDOW(w), 640, 480);
    GtkWidget *l = gtk_label_new("HanonymOS Desktop");
    gtk_container_add(GTK_CONTAINER(w), l);
    gtk_widget_show_all(w);
}
int main(int argc, char **argv) {
    GtkApplication *app = gtk_application_new(
        "os.hanonym.hello", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int r = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return r;
}
