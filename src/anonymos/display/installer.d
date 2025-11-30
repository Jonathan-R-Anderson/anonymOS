module anonymos.display.installer;

import anonymos.display.canvas;
import anonymos.display.font_stack;
import anonymos.display.framebuffer : g_fb;

import anonymos.display.input_pipeline;
import anonymos.console : printLine;
import anonymos.drivers.network : isNetworkAvailable, g_netDevice, NetworkDeviceType;

// Calamares Module Types
public enum CalamaresModule
{
    Welcome,
    NetInstall,
    Blockchain,
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

    // Blockchain
    char[64] walletAddress;
    char[64] contractAddress;
    bool contractDeployed;

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
    
    int windowX;
    int windowY;
    int windowW;
    int windowH;
}

__gshared CalamaresInstaller g_installer;

// Network activity tracking
private __gshared uint g_lastTxPackets = 0;
private __gshared uint g_lastRxPackets = 0;
private __gshared uint g_txPackets = 0;
private __gshared uint g_rxPackets = 0;
private __gshared bool g_networkLinkUp = false;
private __gshared ulong g_lastNetworkUpdate = 0;

// Public function to update packet counts (called by network stack)
public @nogc nothrow void updateInstallerNetworkActivity(uint txPackets, uint rxPackets)
{
    g_txPackets = txPackets;
    g_rxPackets = rxPackets;
}

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
    setStr(g_installer.config.walletAddress, "0x71C7656EC7ab88b098defB751B7401B5f6d8976F");
    
    // Simulate detecting USBs
    g_installer.config.usbDecoyDetected = true;
    setStr(g_installer.config.decoyIsoPath, "/dev/sdb1 (Decoy ISO)");
    
    g_installer.config.usbHiddenDetected = true;
    setStr(g_installer.config.hiddenIsoPath, "/dev/sdc1 (AnonymOS ISO)");
}

// Main render function
public @nogc nothrow void renderInstallerWindow(Canvas* c, int x, int y, int w, int h)
{
    import anonymos.console : printLine, print, printUnsigned;
    static int frameCount = 0;
    frameCount++;
    if (frameCount % 60 == 0)
    {
        print("[installer] render frame "); printUnsigned(frameCount);
        print(" x="); printUnsigned(x);
        print(" y="); printUnsigned(y);
        print(" w="); printUnsigned(w);
        print(" h="); printUnsigned(h);
        print(" module="); printUnsigned(cast(uint)g_installer.currentModule);
        print(" clip="); printUnsigned(c.clipW); print("x"); printUnsigned(c.clipH);
        printLine("");
    }
    // Draw Window Frame
    (*c).canvasRect(x, y, w, h, COL_MAIN_BG);
    
    // Network Status Bar (Top)
    renderNetworkStatusBar(c, x, y, w);
    
    // Adjust content area to account for status bar
    int statusBarHeight = 30;
    y += statusBarHeight;
    h -= statusBarHeight;
    
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
    drawSidebarItem(c, x, menuY + 40, "Network & ZkSync", g_installer.currentModule == CalamaresModule.NetInstall);
    drawSidebarItem(c, x, menuY + 80, "Blockchain Identity", g_installer.currentModule == CalamaresModule.Blockchain);
    drawSidebarItem(c, x, menuY + 120, "Partitions (Veracrypt)", g_installer.currentModule == CalamaresModule.Partition);
    drawSidebarItem(c, x, menuY + 160, "Users", g_installer.currentModule == CalamaresModule.Users);
    drawSidebarItem(c, x, menuY + 200, "Summary", g_installer.currentModule == CalamaresModule.Summary);
    drawSidebarItem(c, x, menuY + 240, "Install", g_installer.currentModule == CalamaresModule.Exec || g_installer.currentModule == CalamaresModule.Finished);

    // Main Content Area
    int contentX = x + sidebarW + 30;
    int contentY = y + 30;
    int contentW = w - sidebarW - 60;
    
    final switch (g_installer.currentModule)
    {
        case CalamaresModule.Welcome: renderWelcome(c, contentX, contentY, contentW); break;
        case CalamaresModule.NetInstall: renderNetInstall(c, contentX, contentY, contentW); break;
        case CalamaresModule.Blockchain: renderBlockchain(c, contentX, contentY, contentW); break;
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
    import anonymos.console : print, printLine, printUnsigned;
    
    // Use stored window geometry from compositor
    int w = g_installer.windowW != 0 ? g_installer.windowW : 800;
    int h = g_installer.windowH != 0 ? g_installer.windowH : 500;
    int winX = g_installer.windowX != 0 ? g_installer.windowX : (g_fb.width - w) / 2;
    int winY = g_installer.windowY != 0 ? g_installer.windowY : (g_fb.height - h) / 2;

    // Initialize network status
    updateNetworkStatus();

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
        else if (event.data1 == 9) // Tab
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
            // import anonymos.console : print, printLine, printUnsigned;
            // print("[installer] Key pressed: ");
            // printUnsigned(cast(uint)event.data1);
            // printLine("");
            handleTextInput(event.data1); // Use translated ASCII
            return true;
        }
    }
    else if (event.type == InputEvent.Type.buttonDown)
    {
        // Mouse Click Handling
        // event.data1 = X
        // event.data2 = Y
        // event.data3 = Buttons
        
        int mx = event.data1;
        int my = event.data2;
        
        // Check Navigation Buttons
        // Back: winX + w - 240, winY + h - 60, 100x36
        // Next: winX + w - 120, winY + h - 60, 100x36
        
        int backX = winX + w - 240;
        int backY = winY + h - 60;
        
        int nextX = winX + w - 120;
        int nextY = winY + h - 60;
        
        // Debug logging
        import anonymos.console : print, printLine, printUnsigned;
        print("[installer] Click at (");
        printUnsigned(cast(uint)mx);
        print(", ");
        printUnsigned(cast(uint)my);
        print(") Next button: (");
        printUnsigned(cast(uint)nextX);
        print(", ");
        printUnsigned(cast(uint)nextY);
        print(") to (");
        printUnsigned(cast(uint)(nextX + 100));
        print(", ");
        printUnsigned(cast(uint)(nextY + 36));
        printLine(")");
        
        if (mx >= nextX && mx <= nextX + 100 && my >= nextY && my <= nextY + 36)
        {
            printLine("[installer] NEXT button clicked!");
            nextModule();
            return true;
        }

        if (mx >= backX && mx <= backX + 100 && my >= backY && my <= backY + 36)
        {
            printLine("[installer] BACK button clicked!");
            prevModule();
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
            if (my >= sidebarY + itemH && my < sidebarY + itemH*2) { g_installer.currentModule = CalamaresModule.NetInstall; return true; }
            if (my >= sidebarY + itemH*2 && my < sidebarY + itemH*3) { g_installer.currentModule = CalamaresModule.Blockchain; return true; }
            if (my >= sidebarY + itemH*3 && my < sidebarY + itemH*4) { g_installer.currentModule = CalamaresModule.Partition; return true; }
            if (my >= sidebarY + itemH*4 && my < sidebarY + itemH*5) { g_installer.currentModule = CalamaresModule.Users; return true; }
            if (my >= sidebarY + itemH*5 && my < sidebarY + itemH*6) { g_installer.currentModule = CalamaresModule.Summary; return true; }
            if (my >= sidebarY + itemH*6 && my < sidebarY + itemH*7) { g_installer.currentModule = CalamaresModule.Exec; return true; }
        }

        // Handle Deploy Button in Blockchain Module
        if (g_installer.currentModule == CalamaresModule.Blockchain && !g_installer.config.contractDeployed)
        {
            // Button at contentX, contentY + 160
            // contentX = winX + 250, contentY = winY + 30
            // Button X: winX + 250, Y: winY + 190, W: 200, H: 40
            int btnX = winX + 250;
            int btnY = winY + 190;
            if (mx >= btnX && mx <= btnX + 200 && my >= btnY && my <= btnY + 40)
            {
                // printLine("[installer] Deploying contract...");
                g_installer.config.contractDeployed = true;
                setStr(g_installer.config.contractAddress, "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7");
                return true;
            }
        }
        
        // Field Hit Testing - enable editing when clicking in content area
        if (mx > winX + 220 && mx < winX + w && my > winY + 30 && my < winY + h - 60)
        {
             // If not already editing, enable editing mode
             if (!g_installer.editingField)
             {
                 import anonymos.console : printLine;
                 
                 // Perform precise hit testing to select the correct field
                 if (hitTestFields(mx, my, winX, winY))
                 {
                     printLine("[installer] Enabling edit mode");
                     g_installer.editingField = true;
                     return true;
                 }
             }
             else
             {
                 // Already editing, but maybe clicked a different field?
                 if (hitTestFields(mx, my, winX, winY))
                 {
                     return true;
                 }
             }
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
        
        // Show help text for connecting
        (*c).canvasRect(x, y + 65, w - 40, 120, 0xFFFFF3CD);
        (*c).canvasRect(x, y + 65, w - 40, 120, 0xFFF39C12, false);
        drawString(c, x + 10, y + 75, "⚠ Network Configuration Required", 0xFFE67E22);
        drawString(c, x + 10, y + 95, "To enable internet access:", 0xFF7F8C8D);
        drawString(c, x + 10, y + 110, "• For QEMU: Add -netdev user,id=net0 -device e1000,netdev=net0", 0xFF7F8C8D);
        drawString(c, x + 10, y + 125, "• For VirtualBox: Enable Network Adapter in VM settings", 0xFF7F8C8D);
        drawString(c, x + 10, y + 140, "• For VMware: Ensure network adapter is set to NAT or Bridged", 0xFF7F8C8D);
        drawString(c, x + 10, y + 155, "• For bare metal: Check physical network cable connection", 0xFF7F8C8D);
    }
    
    // ZkSync Config (adjusted Y positions)
    int configY = isNetworkAvailable() ? y + 80 : y + 200;
    drawString(c, x, configY, "ZkSync Access Point", COL_ACCENT);
    drawField(c, x, configY + 30, "RPC Endpoint:", g_installer.config.zkSyncEndpoint, 0);
    drawField(c, x, configY + 95, "Operator Key (Optional):", g_installer.config.zkSyncOperatorKey, 1, true);
    
    // IP Config (adjusted Y positions)
    drawString(c, x, configY + 170, "IP Configuration", COL_ACCENT);
    drawField(c, x, configY + 200, "Static IP:", g_installer.config.staticIp, 2);
    drawField(c, x, configY + 265, "Gateway:", g_installer.config.gateway, 3);
}

private @nogc nothrow void renderBlockchain(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Blockchain Identity Setup", COL_TEXT_MAIN, 2);
    
    drawString(c, x, y + 40, "Wallet Connected:", COL_TEXT_MAIN);
    drawString(c, x + 160, y + 40, cast(char[])g_installer.config.walletAddress, 0xFF27AE60);
    
    drawString(c, x, y + 80, "Smart Contract:", COL_ACCENT);
    
    if (!g_installer.config.contractDeployed)
    {
        drawString(c, x, y + 110, "Deploy your Identity Contract to the ZkSync network.", COL_TEXT_MAIN);
        drawString(c, x, y + 130, "This contract will track your file fingerprints.", COL_TEXT_MAIN);
        
        // Draw Deploy Button
        (*c).canvasRect(x, y + 160, 200, 40, COL_BUTTON);
        drawString(c, x + 40, y + 170, "Deploy Contract", COL_BUTTON_TEXT);
    }
    else
    {
        drawString(c, x, y + 110, "Contract Deployed Successfully!", 0xFF27AE60);
        drawString(c, x, y + 140, "Address:", COL_TEXT_MAIN);
        drawString(c, x + 80, y + 140, cast(char[])g_installer.config.contractAddress, COL_TEXT_MAIN);
        
        drawString(c, x, y + 180, "Status: Waiting for first fingerprint...", 0xFFE67E22); // Orange
    }
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
    drawField(c, x, y + 115, "Decoy Password:", g_installer.config.decoyPassword, 0, true);
    
    // Hidden
    uint colHidden = g_installer.config.usbHiddenDetected ? 0xFF27AE60 : 0xFFC0392B;
    drawString(c, x, y + 175, "2. Hidden OS Source:", COL_TEXT_MAIN);
    drawString(c, x + 180, y + 175, cast(char[])g_installer.config.hiddenIsoPath, colHidden);
    drawField(c, x, y + 200, "Hidden Password:", g_installer.config.hiddenPassword, 1, true);
    
    drawString(c, x, y + 260, "This will create a hidden volume partition layout.", COL_TEXT_MAIN);
}

private @nogc nothrow void renderUsers(Canvas* c, int x, int y, int w)
{
    drawString(c, x, y, "Create User Account", COL_TEXT_MAIN, 2);
    
    drawField(c, x, y + 60, "What is your name?", g_installer.config.username, 0);
    drawField(c, x, y + 105, "What name do you want to use to log in?", g_installer.config.username, 1);
    drawField(c, x, y + 150, "What is the name of this computer?", g_installer.config.hostname, 2);
    drawField(c, x, y + 195, "Choose a password:", g_installer.config.userPassword, 3, true);
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
    import anonymos.console : printLine, print, printUnsigned;
    // Log field state occasionally
    static int fieldLogCounter = 0;
    fieldLogCounter++;
    if (fieldLogCounter % 300 == 0 && g_installer.selectedIndex == index)
    {
        import anonymos.console : printCString;
        print("[installer] drawField "); printCString(label);
        print(" len="); printUnsigned(stringLen(buffer));
        print(" editing="); printUnsigned(g_installer.editingField ? 1 : 0);
        printLine("");
    }
    drawString(c, x, y, label, COL_TEXT_MAIN);
    
    uint bgCol = (g_installer.selectedIndex == index) ? 0xFFFFFFFF : 0xFFFCFCFC;
    uint borderCol = (g_installer.selectedIndex == index) ? COL_ACCENT : 0xFFBDC3C7;
    
    // Increased spacing: label at y, box at y + 30 to prevent overlap
    (*c).canvasRect(x, y + 30, 300, 30, borderCol);
    (*c).canvasRect(x + 1, y + 31, 298, 28, bgCol);
    
    // Clip text content to the box
    canvasSetClip(*c, x + 1, y + 31, 298, 28);

    // Check if buffer is empty
    bool isEmpty = (buffer[0] == 0);
    
    if (password && !isEmpty)
    {
        drawString(c, x + 5, y + 35, "********", COL_TEXT_MAIN);
    }
    else if (!isEmpty)
    {
        drawString(c, x + 5, y + 35, cast(char[])buffer, COL_TEXT_MAIN);
    }
    else if (isEmpty && g_installer.selectedIndex != index)
    {
        // Show placeholder text in gray when field is empty and not selected
        drawString(c, x + 5, y + 35, cast(char[])buffer, 0xFFBDC3C7);
    }
        
    if (g_installer.selectedIndex == index && g_installer.editingField)
    {
        // Draw cursor
        import anonymos.display.canvas : measureText;
        uint textWidth = 0;
        if (password && !isEmpty)
        {
             // Measure asterisks
             // We don't have a string of asterisks, so we approximate or construct one?
             // Or just measure "********" if that's what we drew.
             // The draw code draws "********" if password && !isEmpty.
             textWidth = measureText(null, "********");
        }
        else if (!isEmpty)
        {
            textWidth = measureText(null, cast(char[])buffer[0..stringLen(buffer)]);
        }
        
        (*c).canvasRect(x + 5 + textWidth, y + 35, 2, 14, COL_TEXT_MAIN);
    }
    
    canvasResetClip(*c);
}

private @nogc nothrow void drawField(Canvas* c, int x, int y, const(char)* label, ref char[64] buffer, int index, bool password = false)
{
    // Overload for 64-byte buffers
    drawString(c, x, y, label, COL_TEXT_MAIN);
    
    uint bgCol = (g_installer.selectedIndex == index) ? 0xFFFFFFFF : 0xFFFCFCFC;
    uint borderCol = (g_installer.selectedIndex == index) ? COL_ACCENT : 0xFFBDC3C7;
    
    // Increased spacing: label at y, box at y + 30 to prevent overlap
    (*c).canvasRect(x, y + 30, 300, 30, borderCol);
    (*c).canvasRect(x + 1, y + 31, 298, 28, bgCol);
    
    // Clip text content to the box
    canvasSetClip(*c, x + 1, y + 31, 298, 28);

    // Check if buffer is empty
    bool isEmpty = (buffer[0] == 0);
    
    if (password && !isEmpty)
    {
        drawString(c, x + 5, y + 35, "********", COL_TEXT_MAIN);
    }
    else if (!isEmpty)
    {
        drawString(c, x + 5, y + 35, cast(char[])buffer, COL_TEXT_MAIN);
    }
    else if (isEmpty && g_installer.selectedIndex != index)
    {
        // Show placeholder text in gray when field is empty and not selected
        drawString(c, x + 5, y + 35, cast(char[])buffer, 0xFFBDC3C7);
    }
        
    if (g_installer.selectedIndex == index && g_installer.editingField)
    {
        import anonymos.display.canvas : measureText;
        uint textWidth = 0;
        if (password && !isEmpty)
        {
             textWidth = measureText(null, "********");
        }
        else if (!isEmpty)
        {
            textWidth = measureText(null, cast(char[])buffer[0..stringLen(buffer)]);
        }
        (*c).canvasRect(x + 5 + textWidth, y + 35, 2, 14, COL_TEXT_MAIN);
    }
    
    canvasResetClip(*c);
}

private @nogc nothrow void nextModule()
{
    if (g_installer.currentModule == CalamaresModule.Welcome) g_installer.currentModule = CalamaresModule.NetInstall;
    else if (g_installer.currentModule == CalamaresModule.NetInstall) g_installer.currentModule = CalamaresModule.Blockchain;
    else if (g_installer.currentModule == CalamaresModule.Blockchain) g_installer.currentModule = CalamaresModule.Partition;
    else if (g_installer.currentModule == CalamaresModule.Partition) g_installer.currentModule = CalamaresModule.Users;
    else if (g_installer.currentModule == CalamaresModule.Users) g_installer.currentModule = CalamaresModule.Summary;
    else if (g_installer.currentModule == CalamaresModule.Summary) 
    {
        g_installer.currentModule = CalamaresModule.Exec;
    }
}

private @nogc nothrow void prevModule()
{
    if (g_installer.currentModule == CalamaresModule.NetInstall) g_installer.currentModule = CalamaresModule.Welcome;
    else if (g_installer.currentModule == CalamaresModule.Blockchain) g_installer.currentModule = CalamaresModule.NetInstall;
    else if (g_installer.currentModule == CalamaresModule.Partition) g_installer.currentModule = CalamaresModule.Blockchain;
    else if (g_installer.currentModule == CalamaresModule.Users) g_installer.currentModule = CalamaresModule.Partition;
    else if (g_installer.currentModule == CalamaresModule.Summary) g_installer.currentModule = CalamaresModule.Users;
}

private @nogc nothrow void handleTextInput(ulong key)
{
    char[] buf = getActiveBuffer();
    if (buf.length == 0) return;
    
    int len = 0;
    while(len < buf.length && buf[len] != 0) len++;
    
    // Handle backspace
    if (key == 8) // Backspace (ASCII)
    {
        if (len > 0)
        {
            buf[len - 1] = 0;
        }
        return;
    }
    
    // Printable characters
    if (key >= 32 && key <= 126)
    {
        if (len < buf.length - 1)
        {
            buf[len] = cast(char)key;
            buf[len + 1] = 0;
        }
    }
}

private @nogc nothrow char[] getActiveBuffer()
{
    // Return slice to the active config field
    if (g_installer.currentModule == CalamaresModule.NetInstall)
    {
        if (g_installer.selectedIndex == 0) return g_installer.config.zkSyncEndpoint[];
        if (g_installer.selectedIndex == 1) return g_installer.config.zkSyncOperatorKey[];
        if (g_installer.selectedIndex == 2) return g_installer.config.staticIp[];
        if (g_installer.selectedIndex == 3) return g_installer.config.gateway[];
    }
    else if (g_installer.currentModule == CalamaresModule.Partition)
    {
        if (g_installer.selectedIndex == 0) return g_installer.config.decoyPassword[];
        if (g_installer.selectedIndex == 1) return g_installer.config.hiddenPassword[];
    }
    else if (g_installer.currentModule == CalamaresModule.Users)
    {
        if (g_installer.selectedIndex == 0) return g_installer.config.username[];
        if (g_installer.selectedIndex == 1) return g_installer.config.username[]; // Duplicate?
        if (g_installer.selectedIndex == 2) return g_installer.config.hostname[];
        if (g_installer.selectedIndex == 3) return g_installer.config.userPassword[];
    }
    return null;
}

private @nogc nothrow bool hitTestFields(int mx, int my, int winX, int winY)
{
    // Content area offset logic from renderInstallerWindow
    int sidebarW = 220;
    int contentX = winX + sidebarW + 30;
    int contentY = winY + 30;
    
    if (g_installer.currentModule == CalamaresModule.NetInstall)
    {
        int configY = isNetworkAvailable() ? contentY + 80 : contentY + 200;
        
        // Field 0: RPC Endpoint (y + 30) -> Box at y + 60
        if (checkFieldHit(mx, my, contentX, configY + 30)) { g_installer.selectedIndex = 0; return true; }
        
        // Field 1: Operator Key (y + 95) -> Box at y + 125
        if (checkFieldHit(mx, my, contentX, configY + 95)) { g_installer.selectedIndex = 1; return true; }
        
        // Field 2: Static IP (y + 200) -> Box at y + 230
        if (checkFieldHit(mx, my, contentX, configY + 200)) { g_installer.selectedIndex = 2; return true; }
        
        // Field 3: Gateway (y + 265) -> Box at y + 295
        if (checkFieldHit(mx, my, contentX, configY + 265)) { g_installer.selectedIndex = 3; return true; }
    }
    else if (g_installer.currentModule == CalamaresModule.Partition)
    {
        // Field 0: Decoy Password (y + 115)
        if (checkFieldHit(mx, my, contentX, contentY + 115)) { g_installer.selectedIndex = 0; return true; }
        
        // Field 1: Hidden Password (y + 200)
        if (checkFieldHit(mx, my, contentX, contentY + 200)) { g_installer.selectedIndex = 1; return true; }
    }
    else if (g_installer.currentModule == CalamaresModule.Users)
    {
        // Field 0: Name (y + 60)
        if (checkFieldHit(mx, my, contentX, contentY + 60)) { g_installer.selectedIndex = 0; return true; }
        
        // Field 1: Login Name (y + 105)
        if (checkFieldHit(mx, my, contentX, contentY + 105)) { g_installer.selectedIndex = 1; return true; }
        
        // Field 2: Hostname (y + 150)
        if (checkFieldHit(mx, my, contentX, contentY + 150)) { g_installer.selectedIndex = 2; return true; }
        
        // Field 3: Password (y + 195)
        if (checkFieldHit(mx, my, contentX, contentY + 195)) { g_installer.selectedIndex = 3; return true; }
    }
    
    return false;
}

private @nogc nothrow bool checkFieldHit(int mx, int my, int x, int y)
{
    // drawField draws the label at 'y', and the box at 'y + 30'.
    // The box height is 30.
    // So the hit target is from y+30 to y+60.
    // Width is 300.
    return (mx >= x && mx <= x + 300 && my >= y + 30 && my <= y + 60);
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
    import anonymos.display.font_stack : activeFontStack;
    int len = 0;
    while (s[len] != 0) len++;
    (*c).canvasText(activeFontStack(), x, y, s[0..len], color, 0, false); // opaqueBg = false for transparent
}

private @nogc nothrow void drawString(Canvas* c, int x, int y, char[] s, uint color, int scale = 1)
{
    import anonymos.display.canvas : canvasText;
    import anonymos.display.font_stack : activeFontStack;
    
    // Find null terminator
    int len = 0;
    while (len < s.length && s[len] != 0) len++;
    
    if (len > 0)
    {
        (*c).canvasText(activeFontStack(), x, y, s[0..len], color, 0, false);
    }
}

// Helper: Copy string
private @nogc nothrow void copyStr(ref char[128] buf, int offset, const(char)[] s)
{
    for (int i = 0; i < s.length && offset + i < 128; i++) {
        buf[offset + i] = s[i];
    }
}

private @nogc nothrow void copyStr(ref char[64] buf, int offset, const(char)[] s)
{
    for (int i = 0; i < s.length && offset + i < 64; i++) {
        buf[offset + i] = s[i];
    }
}

// Helper: Convert uint to string
private @nogc nothrow int uintToStr(uint val, ref char[128] buf, int offset)
{
    if (val == 0) {
        buf[offset] = '0';
        return 1;
    }
    
    char[16] temp;
    int tempLen = 0;
    uint v = val;
    
    while (v > 0) {
        temp[tempLen++] = cast(char)('0' + (v % 10));
        v /= 10;
    }
    
    // Reverse into buffer
    for (int i = 0; i < tempLen; i++) {
        buf[offset + i] = temp[tempLen - 1 - i];
    }
    
    return tempLen;
}

private @nogc nothrow int uintToStr(uint val, ref char[64] buf, int offset)
{
    if (val == 0) {
        buf[offset] = '0';
        return 1;
    }
    
    char[16] temp;
    int tempLen = 0;
    uint v = val;
    
    while (v > 0) {
        temp[tempLen++] = cast(char)('0' + (v % 10));
        v /= 10;
    }
    
    // Reverse into buffer
    for (int i = 0; i < tempLen; i++) {
        buf[offset + i] = temp[tempLen - 1 - i];
    }
    
    return tempLen;
}

// Update network status
private @nogc nothrow void updateNetworkStatus()
{
    import anonymos.drivers.network : isNetworkAvailable, g_netDevice;
    
    // Get TSC for rate limiting updates
    ulong tsc;
    asm @nogc nothrow {
        rdtsc;
        shl RDX, 32;
        or RAX, RDX;
        mov tsc, RAX;
    }
    
    // Update every ~100ms (assuming 2GHz CPU = 200M cycles)
    if (tsc - g_lastNetworkUpdate < 200_000_000) return;
    g_lastNetworkUpdate = tsc;
    
    if (isNetworkAvailable()) {
        g_networkLinkUp = g_netDevice.initialized;
        
        // In a real implementation, we'd read actual packet counters from the NIC
        // For now, we'll simulate activity
        g_lastTxPackets = g_txPackets;
        g_lastRxPackets = g_rxPackets;
    } else {
        g_networkLinkUp = false;
    }
}

// Render network status bar
private @nogc nothrow void renderNetworkStatusBar(Canvas* c, int x, int y, int w)
{
    updateNetworkStatus();
    
    // Status bar background
    uint bgColor = g_networkLinkUp ? 0xFF1B5E20 : 0xFFB71C1C; // Green or Red
    (*c).canvasRect(x, y, w, 30, bgColor);
    
    // Network icon/status text
    int textX = x + 10;
    int textY = y + 8;
    
    if (isNetworkAvailable()) {
        import anonymos.drivers.network : g_netDevice, NetworkDeviceType;
        
        // Device type
        const(char)[] deviceName;
        if (g_netDevice.type == NetworkDeviceType.E1000) {
            deviceName = "E1000";
        } else if (g_netDevice.type == NetworkDeviceType.VirtIO) {
            deviceName = "VirtIO";
        } else if (g_netDevice.type == NetworkDeviceType.RTL8139) {
            deviceName = "RTL8139";
        } else {
            deviceName = "Unknown";
        }
        
        // Status message
        char[128] statusMsg;
        int offset = 0;
        
        // "Network: "
        copyStr(statusMsg, offset, "Network: ");
        offset += 9;
        
        // Device name
        for (int i = 0; i < deviceName.length; i++) {
            statusMsg[offset++] = deviceName[i];
        }
        
        // Link status
        if (g_networkLinkUp) {
            copyStr(statusMsg, offset, " - Link UP");
            offset += 10;
        } else {
            copyStr(statusMsg, offset, " - Link DOWN");
            offset += 12;
        }
        
        // Activity indicator
        if (g_txPackets != g_lastTxPackets || g_rxPackets != g_lastRxPackets) {
            copyStr(statusMsg, offset, " [ACTIVE]");
            offset += 9;
        }
        
        statusMsg[offset] = 0;
        drawString(c, textX, textY, statusMsg.ptr, 0xFFFFFFFF, 1);
        
        // Packet counters (right side)
        char[64] counterMsg;
        offset = 0;
        copyStr(counterMsg, offset, "TX: ");
        offset += 4;
        offset += uintToStr(g_txPackets, counterMsg, offset);
        copyStr(counterMsg, offset, " RX: ");
        offset += 5;
        offset += uintToStr(g_rxPackets, counterMsg, offset);
        counterMsg[offset] = 0;
        
        drawString(c, x + w - 200, textY, counterMsg.ptr, 0xFFFFFFFF, 1);
    } else {
        drawString(c, textX, textY, "Network: Not Available", 0xFFFFFFFF, 1);
    }
}
