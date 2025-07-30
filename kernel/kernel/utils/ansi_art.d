module kernel.utils.ansi_art;
immutable string ANSI_ART =
    "ESC[1;31mHello from ANSI Art!ESC[0m\n"
    ~ "ESC[1;34mBlue TextESC[0m\n"
    ~ "ESC[HESC[2JThis will clear screen and go to top.";
