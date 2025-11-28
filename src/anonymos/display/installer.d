module anonymos.display.installer;

import anonymos.display.canvas;
import anonymos.display.font_stack;

import anonymos.display.input_pipeline;
import anonymos.console : printLine;
import anonymos.drivers.network : isNetworkAvailable, g_netDevice, NetworkDeviceType;

// Calamares Module Types
public enum CalamaresModule
{
    Welcome,
    NetInstall,
    Partition,
    Users,
    Summary,
    Exec,
    Finished,
    Failed
}

public struct InstallerConfig
{
    // NetInstall (ZkSync & Internet)
    bool useDhcp = true;
    char[32] staticIp;
    char[32] gateway;
    char[64] zkSyncEndpoint;
    char[64] zkSyncOperatorKey;

    // Partition (Veracrypt Dual ISO)
    bool dualBoot = true;
    bool usbDecoyDetected;
    bool usbHiddenDetected;
    char[64] decoyIsoPath;
    char[64] hiddenIsoPath;
    char[64] decoyPassword;
    char[64] hiddenPassword;
    
    // Users
    char[32] username;
    char[32] hostname;
    char[64] userPassword;
}

public struct CalamaresInstaller
{
    bool active;
    CalamaresModule currentModule;
    InstallerConfig config;
    float progress;
    char[128] statusMessage;
    
    // UI State
    int selectedIndex; 
    bool editingField; 
    int fieldCursor;
}

__gshared CalamaresInstaller g_installer;

// Calamares Branding Colors
private enum uint COL_SIDEBAR_BG   = 0xFF292F34; // Dark Slate
private enum uint COL_MAIN_BG      = 0xFFEFF0F1; // Light Grey
private enum uint COL_TEXT_MAIN    = 0xFF31363B; // Near Black
private enum uint COL_TEXT_SIDE    = 0xFFBDC3C7; // Light Grey Text
private enum uint COL_ACCENT       = 0xFF3DAEE9; // KDE Blue
private enum uint COL_BUTTON       = 0xFF3DAEE9; 
private enum uint COL_BUTTON_TEXT  = 0xFFFFFFFF;

// Initialize installer
public @nogc nothrow void initInstaller()
{
    g_installer.active = true;
    g_installer.currentModule = CalamaresModule.Welcome;
    g_installer.progress = 0.0f;
    g_installer.selectedIndex = 0;
    
    // Load defaults (simulating reading settings.conf)
    setStr(g_installer.config.zkSyncEndpoint, "https://mainnet.era.zksync.io");
    setStr(g_installer.config.decoyIsoPath, "Scanning...");
    setStr(g_installer.config.hiddenIsoPath, "Scanning...");
    setStr(g_installer.config.hostname, "anonymos-box");
    
    // Simulate detecting USBs
    g_installer.config.usbDecoyDetected = true;
    setStr(g_installer.config.decoyIsoPath, "/dev/sdb1 (Decoy ISO)");
    
    g_installer.config.usbHiddenDetected = true;
    setStr(g_installer.config.hiddenIsoPath, "/dev/sdc1 (AnonymOS ISO)");
}

// Main render function
public @nogc nothrow void renderInstallerWindow(Canvas* c, int x, int y, int w, int h)
{
    // Draw Window Frame
    (*c).canvasRect(x, y, w, h, COL_MAIN_BG);
    
    // Sidebar (Left)
    int sidebarW = 220;
    (*c).canvasRect(x, y, sidebarW, h, COL_SIDEBAR_BG);
    
    // Sidebar Header (Logo Placeholder)
    (*c).canvasRect(x, y, sidebarW, 60, 0xFF1D2328);
    drawString(c, x + 20, y + 20, "Calamares", 0xFFFFFFFF, 2);
    
    // Sidebar Menu Items
    int menuY = y + 80;
    drawSidebarItem(c, x, menuY, "Welcome", g_installer.currentModule == CalamaresModule.Welcome);
    drawSidebarItem(c, x, menuY + 40, "Network & ZkSync", g_installer.currentModule == CalamaresModule.NetInstall);
    drawSidebarItem(c, x, menuY + 80, "Partitions (Veracrypt)", g_installer.currentModule == CalamaresModule.Partition);
    drawSidebarItem(c, x, menuY + 120, "Users", g_installer.currentModule == CalamaresModule.Users);
    drawSidebarItem(c, x, menuY + 160, "Summary", g_installer.currentModule == CalamaresModule.Summary);
    drawSidebarItem(c, x, menuY + 200, "Install", g_installer.currentModule == CalamaresModule.Exec || g_installer.currentModule == CalamaresModule.Finished);

    // Main Content Area
    int contentX = x + sidebarW + 30;
    int contentY = y + 30;
    int contentW = w - sidebarW - 60;
    
    final switch (g_installer.currentModule)
    {
        case CalamaresModule.Welcome: renderWelcome(c, contentX, contentY, contentW); break;
        case CalamaresModule.NetInstall: renderNetInstall(c, contentX, contentY, contentW); break;
        case CalamaresModule.Partition: renderPartition(c, contentX, contentY, contentW); break;
        case CalamaresModule.Users: renderUsers(c, contentX, contentY, contentW); break;
        case CalamaresModule.Summary: renderSummary(c, contentX, contentY, contentW); break;
        case CalamaresModule.Exec: renderExec(c, contentX, contentY, contentW); break;
        case CalamaresModule.Finished: renderFinished(c, contentX, contentY, contentW); break;
        case CalamaresModule.Failed: renderFailed(c, contentX, contentY, contentW); break;
    }
    
    // Navigation Buttons (Bottom Right)
    if (g_installer.currentModule != CalamaresModule.Exec && 
        g_installer.currentModule != CalamaresModule.Finished &&
        g_installer.currentModule != CalamaresModule.Failed)
    {
        drawNavButtons(c, x + w - 240, y + h - 60);
    }
}

// Input Handling
public @nogc nothrow bool handleInstallerInput(InputEvent event)
{
    import anonymos.display.framebuffer : g_fb;
    
    // Recalculate window geometry to match renderInstallerWindow
    int w = 800;
    int h = 500;
    int winX = (g_fb.width - w) / 2;
    int winY = (g_fb.height - h) / 2;

    if (event.type == InputEvent.Type.keyDown)
    {
        // Global Navigation
        if (event.data1 == 28) // Enter
        {
            if (g_installer.editingField)
            {
                g_installer.editingField = false; // Commit edit
                return true;
            }
            else
            {
                nextModule();
                return true;
            }
        }
        else if (event.data1 == 1) // Esc
        {
            if (g_installer.editingField) 
            {
                g_installer.editingField = false;
                return true;
            }
        }
        else if (event.data1 == 200) // Up
        {
            if (!g_installer.editingField && g_installer.selectedIndex > 0) 
            {
                g_installer.selectedIndex--;
                return true;
            }
        }
        else if (event.data1 == 208) // Down
        {
            if (!g_installer.editingField) 
            {
                g_installer.selectedIndex++;
                return true;
            }
        }
        else if (g_installer.editingField)
        {
            // Handle text input for active field
            handleTextInput(event.data1);
            return true;
        }
    }
    else if (event.type == InputEvent.Type.buttonDown)
    {
        // Mouse Click Handling
        // event.data1 = button (1=left, 2=right, 3=middle)
        // event.data2 = x
        // event.data3 = y
        
        int mx = event.data2;
        int my = event.data3;
        
        // Check Navigation Buttons
        // Back: winX + w - 240, winY + h - 60, 100x36
        // Next: winX + w - 120, winY + h - 60, 100x36
        
        int backX = winX + w - 240;
        int backY = winY + h - 60;
        
        int nextX = winX + w - 120;
        int nextY = winY + h - 60;
        
        if (mx >= nextX && mx <= nextX + 100 && my >= nextY && my <= nextY + 36)
        {
            nextModule();
            return true;
        }
        
        // Sidebar Hit Testing
        // x, y+80, 220x40 per item
        int sidebarX = winX;
        int sidebarY = winY + 80;
        int itemH = 40;
        
        if (mx >= sidebarX && mx <= sidebarX + 220)
        {
            if (my >= sidebarY && my < sidebarY + itemH) { g_installer.currentModule = CalamaresModule.Welcome; return true; }
            if (my >= sidebarY + itemH && my < sidebarY + itemH*2) { g_installer.currentModule = CalamaresModule.NetInstall; return true; }
            if (my >= sidebarY + itemH*2 && my < sidebarY + itemH*3) { g_installer.currentModule = CalamaresModule.Partition; return true; }
            if (my >= sidebarY + itemH*3 && my < sidebarY + itemH*4) { g_installer.currentModule = CalamaresModule.Users; return true; }
            if (my >= sidebarY + itemH*4 && my < sidebarY + itemH*5) { g_installer.currentModule = CalamaresModule.Summary; return true; }
            if (my >= sidebarY + itemH*5 && my < sidebarY + itemH*6) { g_installer.currentModule = CalamaresModule.Exec; return true; }
        }
        
        // Field Hit Testing (Simplified)
        // We just check if we clicked in the content area and cycle focus for now, 
        // or we could implement precise hit testing if we knew the field layout per page.
        // For now, let's just say clicking in the content area toggles edit mode if a field is selected.
        if (mx > winX + 220 && mx < winX + w && my > winY && my < winY + h)
        {
             // Placeholder: clicking content area enables editing of currently selected field
             // g_installer.editingField = true;
             // return true;
        }
    }
    
    return false;
}

// --- Page Renderers ---

private @nogc nothrow void renderWelcome(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Welcome to the AnonymOS Installer", COL_TEXT_MAIN, 2);
    drawString(c, x, y + 50, "This program will ask you some questions and set up AnonymOS on your computer.", COL_TEXT_MAIN);
    
    drawString(c, x, y + 100, "Language: American English", COL_TEXT_MAIN);
    
    drawString(c, x, y + 200, "Release: 1.0.0 (Calamares Integration)", COL_TEXT_MAIN);
    drawString(c, x, y + 230, "Kernel: AnonymOS Microkernel", COL_TEXT_MAIN);
}

private @nogc nothrow void renderNetInstall(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Network & ZkSync Configuration", COL_TEXT_MAIN, 2);
    
    // Hardware Status
    drawString(c, x, y + 40, "Network Adapter:", COL_TEXT_MAIN);
    if (isNetworkAvailable())
    {
        drawString(c, x + 160, y + 40, "Connected (Intel E1000)", 0xFF27AE60);
    }
    else
    {
        drawString(c, x + 160, y + 40, "Not Connected", 0xFFC0392B);
    }
    
    // ZkSync Config
    drawString(c, x, y + 80, "ZkSync Access Point", COL_ACCENT);
    drawField(c, x, y + 110, "RPC Endpoint:", g_installer.config.zkSyncEndpoint, 0);
    drawField(c, x, y + 150, "Operator Key (Optional):", g_installer.config.zkSyncOperatorKey, 1, true);
    
    // IP Config
    drawString(c, x, y + 200, "IP Configuration", COL_ACCENT);
    drawField(c, x, y + 230, "Static IP:", g_installer.config.staticIp, 2);
    drawField(c, x, y + 270, "Gateway:", g_installer.config.gateway, 3);
}

private @nogc nothrow void renderPartition(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Partitions & Encryption", COL_TEXT_MAIN, 2);
    
    drawString(c, x, y + 40, "Dual-ISO Veracrypt Setup", COL_ACCENT);
    drawString(c, x, y + 60, "The system requires two USB installation media sources.", COL_TEXT_MAIN);
    
    // Decoy
    uint colDecoy = g_installer.config.usbDecoyDetected ? 0xFF27AE60 : 0xFFC0392B;
    drawString(c, x, y + 90, "1. Decoy OS Source:", COL_TEXT_MAIN);
    drawString(c, x + 180, y + 90, cast(char[])g_installer.config.decoyIsoPath, colDecoy);
    drawField(c, x, y + 110, "Decoy Password:", g_installer.config.decoyPassword, 0, true);
    
    // Hidden
    uint colHidden = g_installer.config.usbHiddenDetected ? 0xFF27AE60 : 0xFFC0392B;
    drawString(c, x, y + 160, "2. Hidden OS Source:", COL_TEXT_MAIN);
    drawString(c, x + 180, y + 160, cast(char[])g_installer.config.hiddenIsoPath, colHidden);
    drawField(c, x, y + 180, "Hidden Password:", g_installer.config.hiddenPassword, 1, true);
    
    drawString(c, x, y + 240, "This will create a hidden volume partition layout.", COL_TEXT_MAIN);
}

private @nogc nothrow void renderUsers(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Create User Account", COL_TEXT_MAIN, 2);
    
    drawField(c, x, y + 60, "What is your name?", g_installer.config.username, 0);
    drawField(c, x, y + 100, "What name do you want to use to log in?", g_installer.config.username, 1);
    drawField(c, x, y + 140, "What is the name of this computer?", g_installer.config.hostname, 2);
    drawField(c, x, y + 180, "Choose a password:", g_installer.config.userPassword, 3, true);
}

private @nogc nothrow void renderSummary(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Summary", COL_TEXT_MAIN, 2);
    
    drawString(c, x, y + 40, "Location: American English", COL_TEXT_MAIN);
    drawString(c, x, y + 70, "Keyboard: US Default", COL_TEXT_MAIN);
    
    drawString(c, x, y + 110, "Partitions:", COL_TEXT_MAIN);
    drawString(c, x + 20, y + 130, "- Create Veracrypt Outer Volume (Decoy OS)", COL_TEXT_MAIN);
    drawString(c, x + 20, y + 150, "- Create Veracrypt Hidden Volume (AnonymOS)", COL_TEXT_MAIN);
    
    drawString(c, x, y + 190, "Network:", COL_TEXT_MAIN);
    drawString(c, x + 20, y + 210, "- ZkSync: Mainnet", COL_TEXT_MAIN);
    
    drawString(c, x, y + 260, "Install AnonymOS now?", COL_BUTTON);
}

private @nogc nothrow void renderExec(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Installing AnonymOS...", COL_TEXT_MAIN, 2);
    
    // Progress Bar
    int barW = w - 40;
    int barH = 20;
    (*c).canvasRect(x, y + 60, barW, barH, 0xFFBDC3C7);
    int fillW = cast(int)(barW * g_installer.progress);
    (*c).canvasRect(x, y + 60, fillW, barH, COL_BUTTON);
    
    drawString(c, x, y + 90, cast(char[])g_installer.statusMessage, COL_TEXT_MAIN);
}

private @nogc nothrow void renderFinished(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "All Done.", COL_TEXT_MAIN, 2);
    drawString(c, x, y + 50, "AnonymOS has been installed on your computer.", COL_TEXT_MAIN);
    drawString(c, x, y + 80, "You may now restart into your new system.", COL_TEXT_MAIN);
    
    (*c).canvasRect(x + w/2 - 60, y + 150, 120, 40, COL_BUTTON);
    drawString(c, x + w/2 - 30, y + 160, "Restart Now", COL_BUTTON_TEXT);
}

private @nogc nothrow void renderFailed(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Installation Failed", 0xFFC0392B, 2);
    drawString(c, x, y + 60, cast(char[])g_installer.statusMessage, COL_TEXT_MAIN);
}

// --- Helpers ---

private @nogc nothrow void drawSidebarItem(Canvas* c, int x, int y, const(char)* text, bool active)
{
    if (active)
    {
        (*c).canvasRect(x, y, 220, 40, 0xFF31363B); // Darker highlight
        drawString(c, x + 20, y + 10, text, COL_ACCENT);
    }
    else
    {
        drawString(c, x + 20, y + 10, text, COL_TEXT_SIDE);
    }
}

private @nogc nothrow void drawNavButtons(Canvas* c, int x, int y)
{
    // Back
    (*c).canvasRect(x, y, 100, 36, 0xFFBDC3C7);
    drawString(c, x + 30, y + 8, "Back", COL_TEXT_MAIN);
    
    // Next
    (*c).canvasRect(x + 120, y, 100, 36, COL_BUTTON);
    drawString(c, x + 150, y + 8, "Next", COL_BUTTON_TEXT);
}

private @nogc nothrow void drawField(Canvas* c, int x, int y, const(char)* label, ref char[32] buffer, int index, bool password = false)
{
    drawString(c, x, y, label, COL_TEXT_MAIN);
    
    uint bgCol = (g_installer.selectedIndex == index) ? 0xFFFFFFFF : 0xFFFCFCFC;
    uint borderCol = (g_installer.selectedIndex == index) ? COL_ACCENT : 0xFFBDC3C7;
    
    (*c).canvasRect(x, y + 20, 300, 30, borderCol);
    (*c).canvasRect(x + 1, y + 21, 298, 28, bgCol);
    
    if (password)
        drawString(c, x + 5, y + 25, "********", COL_TEXT_MAIN);
    else
        drawString(c, x + 5, y + 25, cast(char[])buffer, COL_TEXT_MAIN);
        
    if (g_installer.selectedIndex == index && g_installer.editingField)
    {
        // Draw cursor
        (*c).canvasRect(x + 5 + (stringLen(buffer) * 8), y + 25, 2, 14, COL_TEXT_MAIN);
    }
}

private @nogc nothrow void drawField(Canvas* c, int x, int y, const(char)* label, ref char[64] buffer, int index, bool password = false)
{
    // Overload for 64-byte buffers
    drawString(c, x, y, label, COL_TEXT_MAIN);
    
    uint bgCol = (g_installer.selectedIndex == index) ? 0xFFFFFFFF : 0xFFFCFCFC;
    uint borderCol = (g_installer.selectedIndex == index) ? COL_ACCENT : 0xFFBDC3C7;
    
    (*c).canvasRect(x, y + 20, 300, 30, borderCol);
    (*c).canvasRect(x + 1, y + 21, 298, 28, bgCol);
    
    if (password)
        drawString(c, x + 5, y + 25, "********", COL_TEXT_MAIN);
    else
        drawString(c, x + 5, y + 25, cast(char[])buffer, COL_TEXT_MAIN);
        
    if (g_installer.selectedIndex == index && g_installer.editingField)
    {
        (*c).canvasRect(x + 5 + (stringLen(buffer) * 8), y + 25, 2, 14, COL_TEXT_MAIN);
    }
}

private @nogc nothrow void nextModule()
{
    if (g_installer.currentModule == CalamaresModule.Welcome) g_installer.currentModule = CalamaresModule.NetInstall;
    else if (g_installer.currentModule == CalamaresModule.NetInstall) g_installer.currentModule = CalamaresModule.Partition;
    else if (g_installer.currentModule == CalamaresModule.Partition) g_installer.currentModule = CalamaresModule.Users;
    else if (g_installer.currentModule == CalamaresModule.Users) g_installer.currentModule = CalamaresModule.Summary;
    else if (g_installer.currentModule == CalamaresModule.Summary) 
    {
        g_installer.currentModule = CalamaresModule.Exec;
    }
}

private @nogc nothrow void handleTextInput(ulong key)
{
    // Basic text input handler
    char c = 0;
    if (key >= 0x02 && key <= 0x0B) c = cast(char)('0' + (key - 1) % 10); // 1-9, 0
    if (key == 57) c = ' ';
    else if (key >= 16 && key <= 25) c = cast(char)('q' + (key - 16)); // q-p
    else if (key >= 30 && key <= 38) c = cast(char)('a' + (key - 30)); // a-l
    
    // TODO: Append to buffer
}

private @nogc nothrow void setStr(ref char[32] buf, const(char)* s)
{
    int i = 0;
    while (s[i] != 0 && i < 31) { buf[i] = s[i]; i++; }
    buf[i] = 0;
}
private @nogc nothrow void setStr(ref char[64] buf, const(char)* s)
{
    int i = 0;
    while (s[i] != 0 && i < 63) { buf[i] = s[i]; i++; }
    buf[i] = 0;
}
private @nogc nothrow int stringLen(ref char[32] buf) { int i=0; while(i<32 && buf[i]!=0) i++; return i; }
private @nogc nothrow int stringLen(ref char[64] buf) { int i=0; while(i<64 && buf[i]!=0) i++; return i; }

private @nogc nothrow void drawString(Canvas* c, int x, int y, const(char)* s, uint color, int scale = 1)
{
    import anonymos.display.canvas : canvasText;
    int len = 0;
    while (s[len] != 0) len++;
    (*c).canvasText(null, x, y, s[0..len], color, 0); 
}

private @nogc nothrow void drawString(Canvas* c, int x, int y, char[] s, uint color, int scale = 1)
{
    import anonymos.display.canvas : canvasText;
    (*c).canvasText(null, x, y, s, color, 0);
}
