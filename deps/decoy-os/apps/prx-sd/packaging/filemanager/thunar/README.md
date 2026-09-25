# Thunar: PRX-SD Right-Click Scan Integration

Thunar uses a GUI-based custom action system. To add "Scan with PRX-SD":

1. Open Thunar
2. Go to **Edit > Configure custom actions...**
3. Click the **+** button to add a new action
4. Fill in the fields:
   - **Name:** Scan with PRX-SD
   - **Description:** Scan selected files for malware
   - **Command:** `sd scan %F`
   - **Icon:** security-high
5. In the **Appearance Conditions** tab:
   - Check all file types (Directories, Text Files, etc.)
6. Click **OK** to save

The action will now appear in the right-click context menu for all files and directories.
