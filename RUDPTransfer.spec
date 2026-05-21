# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, copy_metadata
from PyInstaller.building.datastruct import Tree

# Use Kivy's official PyInstaller hook helpers instead of collect_submodules('kivy').
# collect_submodules('kivy') may enter kivy.garden and fail with:
# ValueError: path must be None or list of paths to look for modules in
from kivy.tools.packaging.pyinstaller_hooks import get_deps_all, hookspath, runtime_hooks

block_cipher = None
project_dir = Path(SPECPATH).resolve()

# Kivy provider dependencies. get_deps_all() returns hiddenimports/excludes used by Kivy.
kivy_deps = get_deps_all()
hiddenimports = list(kivy_deps.get('hiddenimports', []))
excludes = list(kivy_deps.get('excludes', []))

# Project/runtime modules that are used by worker mode or dynamically by PyInstaller hooks.
hiddenimports += [
    'main_kivy',
    'client',
    'server',
    'protocol',
    'crypto',
    'congestion',
    'utils',
    'file_transfer_common',
    'cryptography',
    'cryptography.hazmat.bindings._rust',
    # Kivy FileChooser on Windows may import these pywin32 modules at runtime.
    # Without explicit hidden imports, packaged builds can crash with:
    # ModuleNotFoundError: No module named 'win32timezone'
    'win32timezone',
    'win32api',
    'win32con',
    'win32file',
    'pywintypes',
    'pythoncom',
    'tkinter',
    'tkinter.filedialog',
    'tkinter.messagebox',
]

# Keep the build smaller and avoid unnecessary scientific/GUI packages.
excludes += [
    'matplotlib',
    'numpy',
    'pandas',
    'scipy',
    'PIL.ImageQt',
]

# Data files. collect_data_files('kivy') is safe; it does not scan kivy.garden submodules.
datas = []
datas += collect_data_files('kivy')

# cryptography is usually handled by PyInstaller hooks, but package metadata/data makes
# the folder build less sensitive to hook-version differences.
try:
    datas += collect_data_files('cryptography')
    datas += copy_metadata('cryptography')
except Exception:
    pass

try:
    datas += copy_metadata('kivy')
except Exception:
    pass

try:
    datas += copy_metadata('pywin32')
except Exception:
    pass


fonts_dir = project_dir / 'assets' / 'fonts'
if fonts_dir.exists():
    datas.append((str(fonts_dir), 'assets/fonts'))

for src, dest in [
    (project_dir / 'assets' / 'app.png', 'assets'),
    (project_dir / 'assets' / 'app.ico', 'assets'),
    (project_dir / 'requirements.txt', '.'),
    (project_dir / 'allow_firewall_udp_9999_admin.bat', '.'),
]:
    if src.exists():
        datas.append((str(src), dest))

# Kivy binary dependencies on Windows. These are optional imports depending on how Kivy
# was installed. When available, add them to COLLECT as folders.
dep_bins = []
try:
    from kivy_deps import sdl2
    dep_bins += list(sdl2.dep_bins)
except Exception:
    pass
try:
    from kivy_deps import glew
    dep_bins += list(glew.dep_bins)
except Exception:
    pass
try:
    from kivy_deps import angle
    dep_bins += list(angle.dep_bins)
except Exception:
    pass

# Add cryptography dynamic libraries if the installed wheel exposes any.
binaries = []
try:
    binaries += collect_dynamic_libs('cryptography')
except Exception:
    pass

icon_path = project_dir / 'assets' / 'app.ico'
icon_arg = str(icon_path) if icon_path.exists() else None

a = Analysis(
    ['main_kivy.py'],
    pathex=[str(project_dir)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=hookspath(),
    hooksconfig={},
    runtime_hooks=runtime_hooks(),
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='RUDPTransfer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=icon_arg,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    *[Tree(p) for p in dep_bins],
    strip=False,
    upx=True,
    upx_exclude=[],
    name='RUDPTransfer',
)
