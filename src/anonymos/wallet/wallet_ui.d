module anonymos.wallet.wallet_ui;

import anonymos.wallet.zksync_wallet;
import anonymos.display.canvas;
import anonymos.display.font_stack;
import anonymos.console : printLine, print;

/// Wallet UI state
enum WalletUIState {
    Welcome,
    CreateOrImport,
    GenerateMnemonic,
    DisplayMnemonic,
    ConfirmMnemonic,
    ImportMnemonic,
    SetPassword,
    WalletReady,
}

struct WalletUI {
    WalletUIState state;
    char[256] inputBuffer;
    int inputCursor;
    bool showMnemonic;
    int selectedOption;
}

__gshared WalletUI g_walletUI;

/// Initialize wallet UI
export extern(C) void initWalletUI() @nogc nothrow {
    g_walletUI.state = WalletUIState.Welcome;
    g_walletUI.inputCursor = 0;
    g_walletUI.showMnemonic = false;
    g_walletUI.selectedOption = 0;
    
    initWallet();
}

/// Render wallet UI
export extern(C) void renderWalletUI(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    // Background
    (*c).canvasRect(x, y, w, h, 0xFFF5F5F5);
    
    // Title bar
    (*c).canvasRect(x, y, w, 60, 0xFF2C3E50);
    drawText(c, x + 20, y + 20, "ZkSync Wallet", 0xFFFFFFFF, 2);
    
    int contentY = y + 80;
    
    final switch (g_walletUI.state) {
        case WalletUIState.Welcome:
            renderWelcome(c, x, contentY, w, h - 80);
            break;
        case WalletUIState.CreateOrImport:
            renderCreateOrImport(c, x, contentY, w, h - 80);
            break;
        case WalletUIState.GenerateMnemonic:
            renderGenerateMnemonic(c, x, contentY, w, h - 80);
            break;
        case WalletUIState.DisplayMnemonic:
            renderDisplayMnemonic(c, x, contentY, w, h - 80);
            break;
        case WalletUIState.ConfirmMnemonic:
            renderConfirmMnemonic(c, x, contentY, w, h - 80);
            break;
        case WalletUIState.ImportMnemonic:
            renderImportMnemonic(c, x, contentY, w, h - 80);
            break;
        case WalletUIState.SetPassword:
            renderSetPassword(c, x, contentY, w, h - 80);
            break;
        case WalletUIState.WalletReady:
            renderWalletReady(c, x, contentY, w, h - 80);
            break;
    }
}

private void renderWelcome(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Welcome to ZkSync Wallet", 0xFF2C3E50, 2);
    drawText(c, x + 40, y + 60, "Secure Ethereum wallet for ZkSync Era", 0xFF7F8C8D, 1);
    
    drawText(c, x + 40, y + 120, "This wallet uses BIP39 mnemonic phrases", 0xFF34495E, 1);
    drawText(c, x + 40, y + 145, "for maximum security and compatibility.", 0xFF34495E, 1);
    
    // Button
    drawButton(c, x + w/2 - 100, y + 220, 200, 50, "Get Started", 
               g_walletUI.selectedOption == 0, 0xFF3498DB);
}

private void renderCreateOrImport(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Create or Import Wallet", 0xFF2C3E50, 2);
    
    // Create new wallet button
    drawButton(c, x + 40, y + 100, w - 80, 60, "Create New Wallet",
               g_walletUI.selectedOption == 0, 0xFF27AE60);
    drawText(c, x + 60, y + 175, "Generate a new 12-word recovery phrase", 0xFF7F8C8D, 1);
    
    // Import existing wallet button
    drawButton(c, x + 40, y + 230, w - 80, 60, "Import Existing Wallet",
               g_walletUI.selectedOption == 1, 0xFF3498DB);
    drawText(c, x + 60, y + 305, "Restore wallet from recovery phrase", 0xFF7F8C8D, 1);
}

private void renderGenerateMnemonic(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Generating Recovery Phrase...", 0xFF2C3E50, 2);
    
    // Progress indicator
    (*c).canvasRect(x + 40, y + 80, w - 80, 30, 0xFFECF0F1);
    (*c).canvasRect(x + 40, y + 80, (w - 80) * 3 / 4, 30, 0xFF3498DB);
    
    drawText(c, x + 40, y + 130, "Using hardware RNG (RDRAND)...", 0xFF7F8C8D, 1);
}

private void renderDisplayMnemonic(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Your Recovery Phrase", 0xFF2C3E50, 2);
    
    // Warning box
    (*c).canvasRect(x + 40, y + 60, w - 80, 80, 0xFFFFF3CD);
    (*c).canvasRect(x + 40, y + 60, w - 80, 80, 0xFFF39C12, false);
    drawText(c, x + 60, y + 75, "⚠ IMPORTANT: Write this down!", 0xFFE67E22, 1);
    drawText(c, x + 60, y + 100, "Never share your recovery phrase.", 0xFF7F8C8D, 1);
    drawText(c, x + 60, y + 120, "Anyone with this phrase can access your funds.", 0xFF7F8C8D, 1);
    
    // Display mnemonic
    if (g_walletUI.showMnemonic) {
        (*c).canvasRect(x + 40, y + 160, w - 80, 120, 0xFFFFFFFF);
        (*c).canvasRect(x + 40, y + 160, w - 80, 120, 0xFFBDC3C7, false);
        
        // Get mnemonic from wallet
        extern(C) const(char)* getMnemonic() @nogc nothrow {
            return g_wallet.mnemonic.ptr;
        }
        
        const(char)* mnemonic = getMnemonic();
        drawText(c, x + 60, y + 180, mnemonic, 0xFF2C3E50, 1);
    } else {
        drawButton(c, x + w/2 - 100, y + 200, 200, 50, "Show Phrase",
                   g_walletUI.selectedOption == 0, 0xFF3498DB);
    }
    
    // Continue button
    if (g_walletUI.showMnemonic) {
        drawButton(c, x + w/2 - 100, y + 300, 200, 50, "I've Written It Down",
                   g_walletUI.selectedOption == 1, 0xFF27AE60);
    }
}

private void renderConfirmMnemonic(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Confirm Recovery Phrase", 0xFF2C3E50, 2);
    drawText(c, x + 40, y + 60, "Enter your recovery phrase to confirm:", 0xFF7F8C8D, 1);
    
    // Input box
    (*c).canvasRect(x + 40, y + 100, w - 80, 40, 0xFFFFFFFF);
    (*c).canvasRect(x + 40, y + 100, w - 80, 40, 0xFF3498DB, false);
    
    drawText(c, x + 50, y + 115, g_walletUI.inputBuffer.ptr, 0xFF2C3E50, 1);
    
    // Cursor
    if (g_walletUI.inputCursor > 0) {
        int cursorX = x + 50 + g_walletUI.inputCursor * 8;
        (*c).canvasRect(cursorX, y + 115, 2, 20, 0xFF2C3E50);
    }
    
    // Verify button
    drawButton(c, x + w/2 - 100, y + 180, 200, 50, "Verify",
               g_walletUI.selectedOption == 0, 0xFF27AE60);
}

private void renderImportMnemonic(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Import Wallet", 0xFF2C3E50, 2);
    drawText(c, x + 40, y + 60, "Enter your 12 or 24 word recovery phrase:", 0xFF7F8C8D, 1);
    
    // Input box
    (*c).canvasRect(x + 40, y + 100, w - 80, 100, 0xFFFFFFFF);
    (*c).canvasRect(x + 40, y + 100, w - 80, 100, 0xFF3498DB, false);
    
    drawText(c, x + 50, y + 115, g_walletUI.inputBuffer.ptr, 0xFF2C3E50, 1);
    
    // Import button
    drawButton(c, x + w/2 - 100, y + 230, 200, 50, "Import",
               g_walletUI.selectedOption == 0, 0xFF27AE60);
}

private void renderSetPassword(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Set Wallet Password", 0xFF2C3E50, 2);
    drawText(c, x + 40, y + 60, "Create a password to encrypt your wallet:", 0xFF7F8C8D, 1);
    
    // Password input
    (*c).canvasRect(x + 40, y + 100, w - 80, 40, 0xFFFFFFFF);
    (*c).canvasRect(x + 40, y + 100, w - 80, 40, 0xFF3498DB, false);
    
    // Show asterisks for password
    char[64] masked;
    for (int i = 0; i < g_walletUI.inputCursor && i < 63; i++) {
        masked[i] = '*';
    }
    masked[g_walletUI.inputCursor] = 0;
    
    drawText(c, x + 50, y + 115, masked.ptr, 0xFF2C3E50, 1);
    
    // Create button
    drawButton(c, x + w/2 - 100, y + 180, 200, 50, "Create Wallet",
               g_walletUI.selectedOption == 0, 0xFF27AE60);
}

private void renderWalletReady(Canvas* c, int x, int y, int w, int h) @nogc nothrow {
    drawText(c, x + 40, y + 20, "Wallet Ready!", 0xFF27AE60, 2);
    
    // Success icon
    (*c).canvasRect(x + w/2 - 40, y + 80, 80, 80, 0xFF27AE60);
    drawText(c, x + w/2 - 20, y + 105, "✓", 0xFFFFFFFF, 3);
    
    // Display address
    const(char)* address = getWalletAddress();
    if (address !is null) {
        drawText(c, x + 40, y + 200, "Your Address:", 0xFF7F8C8D, 1);
        
        (*c).canvasRect(x + 40, y + 230, w - 80, 40, 0xFFECF0F1);
        drawText(c, x + 50, y + 245, address, 0xFF2C3E50, 1);
    }
    
    // Continue button
    drawButton(c, x + w/2 - 100, y + 300, 200, 50, "Continue to Installer",
               g_walletUI.selectedOption == 0, 0xFF3498DB);
}

// Helper functions
private void drawText(Canvas* c, int x, int y, const(char)* text, uint color, int scale) @nogc nothrow {
    import anonymos.display.canvas : canvasText;
    
    int len = 0;
    while (text[len] != 0 && len < 256) len++;
    
    (*c).canvasText(activeFontStack(), x, y, text[0..len], color, 0, false);
}

private void drawButton(Canvas* c, int x, int y, int w, int h, const(char)* label,
                        bool selected, uint color) @nogc nothrow {
    uint bgColor = selected ? color : 0xFFECF0F1;
    uint textColor = selected ? 0xFFFFFFFF : 0xFF2C3E50;
    
    (*c).canvasRect(x, y, w, h, bgColor);
    
    if (!selected) {
        (*c).canvasRect(x, y, w, h, color, false);
    }
    
    // Center text
    int textLen = 0;
    while (label[textLen] != 0) textLen++;
    
    int textX = x + (w - textLen * 8) / 2;
    int textY = y + (h - 16) / 2;
    
    drawText(c, textX, textY, label, textColor, 1);
}

/// Handle wallet UI input
export extern(C) bool handleWalletUIInput(ubyte keycode, char character) @nogc nothrow {
    if (keycode == 28) { // Enter
        return handleWalletUIAction();
    } else if (keycode == 200) { // Up
        if (g_walletUI.selectedOption > 0) {
            g_walletUI.selectedOption--;
        }
        return true;
    } else if (keycode == 208) { // Down
        g_walletUI.selectedOption++;
        return true;
    } else if (character != 0) {
        // Text input
        if (g_walletUI.inputCursor < 255) {
            g_walletUI.inputBuffer[g_walletUI.inputCursor++] = character;
            g_walletUI.inputBuffer[g_walletUI.inputCursor] = 0;
        }
        return true;
    }
    
    return false;
}

private bool handleWalletUIAction() @nogc nothrow {
    final switch (g_walletUI.state) {
        case WalletUIState.Welcome:
            g_walletUI.state = WalletUIState.CreateOrImport;
            g_walletUI.selectedOption = 0;
            return true;
            
        case WalletUIState.CreateOrImport:
            if (g_walletUI.selectedOption == 0) {
                // Create new wallet
                generateMnemonic(MnemonicWordCount.Words12);
                g_walletUI.state = WalletUIState.DisplayMnemonic;
            } else {
                // Import wallet
                g_walletUI.state = WalletUIState.ImportMnemonic;
            }
            g_walletUI.selectedOption = 0;
            return true;
            
        case WalletUIState.GenerateMnemonic:
            g_walletUI.state = WalletUIState.DisplayMnemonic;
            return true;
            
        case WalletUIState.DisplayMnemonic:
            if (!g_walletUI.showMnemonic) {
                g_walletUI.showMnemonic = true;
                g_walletUI.selectedOption = 1;
            } else {
                g_walletUI.state = WalletUIState.SetPassword;
                g_walletUI.selectedOption = 0;
            }
            return true;
            
        case WalletUIState.ConfirmMnemonic:
            // TODO: Verify mnemonic
            g_walletUI.state = WalletUIState.SetPassword;
            return true;
            
        case WalletUIState.ImportMnemonic:
            importMnemonic(g_walletUI.inputBuffer.ptr);
            g_walletUI.state = WalletUIState.SetPassword;
            return true;
            
        case WalletUIState.SetPassword:
            // Derive seed and account
            deriveSeedFromMnemonic(g_walletUI.inputBuffer.ptr);
            deriveAccount(0);
            unlockWallet(g_walletUI.inputBuffer.ptr);
            
            g_walletUI.state = WalletUIState.WalletReady;
            return true;
            
        case WalletUIState.WalletReady:
            // Continue to installer
            return false; // Signal completion
    }
}
