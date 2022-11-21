# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_dynamic_libs
block_cipher = None


a = Analysis(
    ['app.py'],
    pathex=['.\\env\\Lib\\site-packages'],
    binaries=collect_dynamic_libs("capstone"),
    datas=[('./data/weightGAT.pt', '.')],
    hiddenimports=[ 'sv_ttk',
                    'tkinterdnd2',
                    'pefile',
                    'capstone',
                    'tqdm',
                    'torch',
                    'torchvision',
                    'torchaudio',
                    'torch-scatter',
                    'torch-sparse',
                    'torch-cluster',
                    'torch-spline-conv',
                    'torch-geometric'
                  ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='main',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )