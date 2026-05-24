const { app, BrowserWindow, nativeImage } = require('electron');
const path = require('path');

app.setName('Seal Wallet');

// Per-platform icon file. Electron picks the right format at window
// creation time: .ico on Windows, .png on Linux. macOS reads the bundle
// Info.plist for the dock icon — for `npm run electron` (no bundling),
// we additionally call app.dock.setIcon() below so the running dock entry
// shows our icon instead of the default Electron diamond.
const ICON_BY_PLATFORM = {
  darwin: 'icon.icns',
  win32: 'icon.ico',
  linux: 'icon.png',
};
const iconPath = path.join(
  __dirname,
  'assets',
  ICON_BY_PLATFORM[process.platform] || 'icon.png',
);

function createWindow() {
  const win = new BrowserWindow({
    width: 520,
    height: 860,
    title: 'Seal Wallet',
    backgroundColor: '#0a0a0f',
    icon: iconPath,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  win.loadFile(path.join(__dirname, 'standalone.html'));
  win.setMenuBarVisibility(false);
}

app.whenReady().then(() => {
  if (process.platform === 'darwin' && app.dock) {
    try {
      app.dock.setIcon(nativeImage.createFromPath(iconPath));
    } catch {
      // Ignore — dock icon is cosmetic in dev mode.
    }
  }
  createWindow();
});
app.on('window-all-closed', () => app.quit());
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
