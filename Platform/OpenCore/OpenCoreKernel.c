/** @file
  OpenCore driver.

Copyright (c) 2019, vit9696. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <OpenCore.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcAppleKernelLib.h>
#include <Library/OcMiscLib.h>
#include <Library/OcStringLib.h>
#include <Library/OcVirtualFsLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

STATIC OC_STORAGE_CONTEXT  *mOcStorage;
STATIC OC_GLOBAL_CONFIG    *mOcConfiguration;
STATIC OC_CPU_INFO         *mOcCpuInfo;

STATIC CHAR16              **mOcInjectedKexts;
STATIC CHAR16              **mOcPatchedKexts;
STATIC CHAR16              **mOcBlockedKexts;

STATIC
VOID
OcKernelReadDarwinVersion (
  IN  CONST UINT8   *Kernel,
  IN  UINT32        KernelSize,
  OUT CHAR8         *DarwinVersion,
  OUT UINT32        DarwinVersionSize
  )
{
  INT32   Offset;
  UINT32  Index;

  ASSERT (DarwinVersion > 0);

  Offset = FindPattern (
    (CONST UINT8 *) "Darwin Kernel Version ",
    NULL,
    L_STR_LEN ("Darwin Kernel Version "),
    Kernel,
    KernelSize,
    0
    );

  if (Offset < 0) {
    DEBUG ((DEBUG_WARN, "OC: Failed to determine kernel version\n"));
    DarwinVersion[0] = '\0';
    return;
  }

  Offset += L_STR_LEN ("Darwin Kernel Version ");

  for (Index = 0; Index < DarwinVersionSize - 1; ++Index, ++Offset) {
    if ((UINT32) Offset >= KernelSize || Kernel[Offset] == ':') {
      break;
    }
    DarwinVersion[Index] = (CHAR8) Kernel[Offset];
  }
  DarwinVersion[Index] = '\0';

  DEBUG ((DEBUG_INFO, "OC: Read kernel version %a\n", DarwinVersion));
}

STATIC
UINT32
OcKernelLoadKextsAndReserve (
  IN OC_STORAGE_CONTEXT  *Storage,
  IN OC_GLOBAL_CONFIG    *Config
  )
{
  UINT32               Index;
  UINT32               ReserveSize;
  CHAR8                *BundlePath;
  CHAR8                *PlistPath;
  CHAR8                *ExecutablePath;
  CHAR16               FullPath[128];
  OC_KERNEL_ADD_ENTRY  *Kext;

  ReserveSize = PRELINK_INFO_RESERVE_SIZE;

  for (Index = 0; Index < Config->Kernel.Add.Count; ++Index) {
    Kext = Config->Kernel.Add.Values[Index];

    if (!Kext->Enabled) {
      continue;
    }

    if (Kext->PlistDataSize == 0) {
      BundlePath     = OC_BLOB_GET (&Kext->BundlePath);
      PlistPath      = OC_BLOB_GET (&Kext->PlistPath);
      if (BundlePath[0] == '\0' || PlistPath[0] == '\0') {
        DEBUG ((DEBUG_ERROR, "OC: Your config has improper for kext info\n"));
        Kext->Enabled = FALSE;
        continue;
      }

      UnicodeSPrint (
        FullPath,
        sizeof (FullPath),
        OPEN_CORE_KEXT_PATH "%a\\%a",
        BundlePath,
        PlistPath
        );

      UnicodeUefiSlashes (FullPath);

      Kext->PlistData = OcStorageReadFileUnicode (
        Storage,
        FullPath,
        &Kext->PlistDataSize
        );

      if (Kext->PlistData == NULL) {
        DEBUG ((DEBUG_ERROR, "OC: Plist %s is missing for kext %a\n", FullPath, BundlePath));
        Kext->Enabled = FALSE;
        continue;
      }

      ExecutablePath = OC_BLOB_GET (&Kext->ExecutablePath);
      if (ExecutablePath[0] != '\0') {
        UnicodeSPrint (
          FullPath,
          sizeof (FullPath),
          OPEN_CORE_KEXT_PATH "%a\\%a",
          BundlePath,
          ExecutablePath
          );

        UnicodeUefiSlashes (FullPath);

        Kext->ImageData = OcStorageReadFileUnicode (
          Storage,
          FullPath,
          &Kext->ImageDataSize
          );

        if (Kext->ImageData == NULL) {
          DEBUG ((DEBUG_ERROR, "OC: Image %s is missing for kext %a\n", FullPath, BundlePath));
          Kext->Enabled = FALSE;
          continue;
        }
      }
    }

    PrelinkedReserveKextSize (
      &ReserveSize,
      Kext->PlistDataSize,
      Kext->ImageData,
      Kext->ImageDataSize
      );
  }

  DEBUG ((DEBUG_INFO, "Kext reservation size %u\n", ReserveSize));

  return ReserveSize;
}

STATIC
RETURN_STATUS
OcKernelApplyPatch (
  IN PATCHER_CONTEXT       *Patcher,
  IN OC_KERNEL_PATCH_ENTRY *UserPatch
  )
{
  PATCHER_GENERIC_PATCH  Patch;

  ASSERT (Patcher != NULL);
  ASSERT (UserPatch != NULL);

  //
  // Ignore patch if:
  // - There is nothing to replace.
  // - We have neither symbolic base, nor find data.
  // - Find and replace mismatch in size.
  // - Mask and ReplaceMask mismatch in size when are available.
  //
  if (UserPatch->Replace.Size == 0
    || (OC_BLOB_GET (&UserPatch->Base)[0] == '\0' && UserPatch->Find.Size != UserPatch->Replace.Size)
    || (UserPatch->Mask.Size > 0 && UserPatch->Find.Size != UserPatch->Mask.Size)
    || (UserPatch->ReplaceMask.Size > 0 && UserPatch->Find.Size != UserPatch->ReplaceMask.Size)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&Patch, sizeof (Patch));

  if (OC_BLOB_GET (&UserPatch->Comment)[0] != '\0') {
    Patch.Comment  = OC_BLOB_GET (&UserPatch->Comment);
  }

  if (OC_BLOB_GET (&UserPatch->Base)[0] != '\0') {
    Patch.Base  = OC_BLOB_GET (&UserPatch->Base);
  }

  if (UserPatch->Find.Size > 0) {
    Patch.Find  = OC_BLOB_GET (&UserPatch->Find);
  }

  Patch.Replace = OC_BLOB_GET (&UserPatch->Replace);

  if (UserPatch->Mask.Size > 0) {
    Patch.Mask  = OC_BLOB_GET (&UserPatch->Mask);
  }

  if (UserPatch->ReplaceMask.Size > 0) {
    Patch.ReplaceMask = OC_BLOB_GET (&UserPatch->ReplaceMask);
  }

  Patch.Size    = UserPatch->Replace.Size;
  Patch.Count   = UserPatch->Count;
  Patch.Skip    = UserPatch->Skip;
  Patch.Limit   = UserPatch->Limit;

  return PatcherApplyGenericPatch (Patcher, &Patch);
}

STATIC
VOID
OcKernelApplyPatches (
  IN     OC_GLOBAL_CONFIG  *Config,
  IN     CONST CHAR8       *DarwinVersion,
  IN     PRELINKED_CONTEXT *Context,
  IN OUT UINT8             *Kernel,
  IN     UINT32            Size
  )
{
  EFI_STATUS             Status;
  PATCHER_CONTEXT        Patcher;
  UINT32                 Index;
  OC_KERNEL_PATCH_ENTRY  *UserPatch;
  CONST CHAR8            *Target;
  CONST CHAR8            *MatchKernel;
  BOOLEAN                IsKernelPatch;

  IsKernelPatch = Context == NULL;

  if (IsKernelPatch) {
    ASSERT (Kernel != NULL);

    Status = PatcherInitContextFromBuffer (
      &Patcher,
      Kernel,
      Size
      );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "OC: Kernel patcher kernel init failure - %r\n", Status));
      return;
    }
  }

  for (Index = 0; Index < Config->Kernel.Patch.Count; ++Index) {
    UserPatch = Config->Kernel.Patch.Values[Index];
    Target    = OC_BLOB_GET (&UserPatch->Identifier);

    if (!UserPatch->Enabled
    || (AsciiStrCmp (Target, "kernel") == 0) != IsKernelPatch) {
      continue;
    }

    MatchKernel = OC_BLOB_GET (&UserPatch->MatchKernel);

    if (AsciiStrnCmp (DarwinVersion, MatchKernel, AsciiStrLen (MatchKernel)) != 0) {
      DEBUG ((
        DEBUG_INFO,
        "OC: Kernel patcher skips %a patch at %u due to version %a vs %a",
        Target,
        Index,
        MatchKernel,
        DarwinVersion
        ));
      continue;
    }

    if (!IsKernelPatch) {
      Status = PatcherInitContextFromPrelinked (
        &Patcher,
        Context,
        Target
        );

      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "OC: Kernel patcher %a init failure - %r\n", Target, Status));
        continue;
      } else {
        DEBUG ((DEBUG_INFO, "OC: Kernel patcher %a init succeed\n", Target));
      }
    }

    Status = OcKernelApplyPatch (&Patcher, UserPatch);
    DEBUG ((
      EFI_ERROR (Status) ? DEBUG_WARN : DEBUG_INFO,
      "OC: Kernel patcher result %u for %a - %r\n",
      Index,
      Target,
      Status
      ));
  }

  if (!IsKernelPatch) {
    if (Config->Kernel.Quirks.AppleCpuPmCfgLock) {
     // PatchAppleCpuPmCfgLock (Context);
    }

    if (Config->Kernel.Quirks.ExternalDiskIcons) {
      PatchForceInternalDiskIcons (Context);
    }

    if (Config->Kernel.Quirks.ThirdPartyTrim) {
      PatchThirdPartySsdTrim (Context);
    }

    if (Config->Kernel.Quirks.XhciPortLimit) {
      PatchUsbXhciPortLimit (Context);
    }

    if (Config->Kernel.Quirks.DisableIoMapper) {
      PatchAppleIoMapperSupport (Context);
    }

    if (Config->Kernel.Quirks.CustomSmbiosGuid) {
      PatchCustomSmbiosGuid (Context);
    }
  } else {
    if (Config->Kernel.Quirks.AppleXcpmCfgLock) {
      PatchAppleXcpmCfgLock (&Patcher);
    }

    if (Config->Kernel.Quirks.AppleXcpmExtraMsrs) {
      PatchAppleXcpmExtraMsrs (&Patcher);
    }

    if (Config->Kernel.Quirks.PanicNoKextDump) {
      PatchPanicKextDump (&Patcher);      
    }

    if (Config->Kernel.Emulate.Cpuid1Data[0] != 0
      || Config->Kernel.Emulate.Cpuid1Data[1] != 0
      || Config->Kernel.Emulate.Cpuid1Data[2] != 0
      || Config->Kernel.Emulate.Cpuid1Data[3] != 0) {
      PatchKernelCpuId (
        &Patcher,
        mOcCpuInfo,
        Config->Kernel.Emulate.Cpuid1Data,
        Config->Kernel.Emulate.Cpuid1Mask
        );
    }

    if (Config->Kernel.Quirks.LapicKernelPanic) {
      PatchLapicKernelPanic (&Patcher);
    }
  }
}

STATIC
VOID
OcKernelBlockKexts (
  IN     OC_GLOBAL_CONFIG  *Config,
  IN     CONST CHAR8       *DarwinVersion,
  IN     PRELINKED_CONTEXT *Context
  )
{
  EFI_STATUS             Status;
  PATCHER_CONTEXT        Patcher;
  UINT32                 Index;
  OC_KERNEL_BLOCK_ENTRY  *Kext;
  CONST CHAR8            *Target;
  CONST CHAR8            *MatchKernel;

  for (Index = 0; Index < Config->Kernel.Block.Count; ++Index) {
    Kext   = Config->Kernel.Block.Values[Index];
    Target = OC_BLOB_GET (&Kext->Identifier);

    if (!Kext->Enabled) {
      continue;
    }

    MatchKernel = OC_BLOB_GET (&Kext->MatchKernel);

    if (AsciiStrnCmp (DarwinVersion, MatchKernel, AsciiStrLen (MatchKernel)) != 0) {
      DEBUG ((
        DEBUG_INFO,
        "OC: Prelink blocker skips %a block at %u due to version %a vs %a",
        Target,
        Index,
        MatchKernel,
        DarwinVersion
        ));
      continue;
    }

    Status = PatcherInitContextFromPrelinked (
      &Patcher,
      Context,
      Target
      );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "OC: Prelink blocker %a init failure - %r\n", Target, Status));
      continue;
    }

    Status = PatcherBlockKext (&Patcher);

    DEBUG ((
      EFI_ERROR (Status) ? DEBUG_WARN : DEBUG_INFO,
      "OC: Prelink blocker %a - %r\n",
      Target,
      Status
      ));
  }
}

STATIC
EFI_STATUS
OcKernelProcessPrelinked (
  IN     OC_GLOBAL_CONFIG  *Config,
  IN     CONST CHAR8       *DarwinVersion,
  IN OUT UINT8             *Kernel,
  IN     UINT32            *KernelSize,
  IN     UINT32            AllocatedSize
  )
{
  EFI_STATUS           Status;
  PRELINKED_CONTEXT    Context;
  CHAR8                *BundlePath;
  CHAR8                *ExecutablePath;
  UINT32               Index;
  CHAR8                FullPath[128];
  OC_KERNEL_ADD_ENTRY  *Kext;
  CONST CHAR8          *MatchKernel;

  Status = PrelinkedContextInit (&Context, Kernel, *KernelSize, AllocatedSize);

  if (!EFI_ERROR (Status)) {
    OcKernelApplyPatches (Config, DarwinVersion, &Context, NULL, 0);

    OcKernelBlockKexts (Config, DarwinVersion, &Context);

    Status = PrelinkedInjectPrepare (&Context);
    if (!EFI_ERROR (Status)) {

      for (Index = 0; Index < Config->Kernel.Add.Count; ++Index) {
        Kext = Config->Kernel.Add.Values[Index];

        if (!Kext->Enabled || Kext->PlistDataSize == 0) {
          continue;
        }

        BundlePath  = OC_BLOB_GET (&Kext->BundlePath);
        MatchKernel = OC_BLOB_GET (&Kext->MatchKernel);

        if (AsciiStrnCmp (DarwinVersion, MatchKernel, AsciiStrLen (MatchKernel)) != 0) {
          DEBUG ((
            DEBUG_INFO,
            "OC: Prelink injection skips %a kext at %u due to version %a vs %a",
            BundlePath,
            Index,
            MatchKernel,
            DarwinVersion
            ));
          continue;
        }

        AsciiSPrint (FullPath, sizeof (FullPath), "/Library/Extensions/%a", BundlePath);
        if (Kext->ImageData != NULL) {
          ExecutablePath = OC_BLOB_GET (&Kext->ExecutablePath);
        } else {
          ExecutablePath = NULL;
        }

        Status = PrelinkedInjectKext (
          &Context,
          FullPath,
          Kext->PlistData,
          Kext->PlistDataSize,
          ExecutablePath,
          Kext->ImageData,
          Kext->ImageDataSize
          );

        DEBUG ((
          EFI_ERROR (Status) ? DEBUG_WARN : DEBUG_INFO,
          "OC: Prelink injection %a - %r\n",
          BundlePath,
          Status
          ));
      }

      Status = PrelinkedInjectComplete (&Context);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "OC: Prelink insertion error - %r\n", Status));
      }
    } else {
      DEBUG ((DEBUG_WARN, "OC: Prelink inject prepare error - %r\n", Status));
    }

    *KernelSize = Context.PrelinkedSize;

    PrelinkedContextFree (&Context);
  }

  return Status;
}

STATIC
EFI_STATUS
OcKernelBuildExtensionsDir (
  IN     OC_GLOBAL_CONFIG  *Config,
  IN OUT EFI_FILE_PROTOCOL  **File,
  IN     CHAR16             *FileName
  )
{
  EFI_STATUS           Status;
  EFI_FILE_INFO        *FileInfo;

  UINTN                DirectorySize;
  UINTN                DirectoryOffset;
  UINT8                *DirectoryBuffer;
  EFI_FILE_PROTOCOL    *VirtualFileHandle;
  EFI_FILE_PROTOCOL    *NewFile;

  UINT32               Index;
  UINT32               IndexClean;
  UINT32               FileNameIndex;
  OC_KERNEL_ADD_ENTRY  *Kext;
  UINTN                BundleFileNameSize;
  UINTN                BundleFileNameLength;

  //
  // Allocate array to maintain kext to name mappings.
  // Names are of format OcXXXXXXXX.kext, where XXXXXXXX is a 32-bit hexadecimal number.
  //
  BundleFileNameSize = L_STR_SIZE (L"OcXXXXXXXX.kext");
  mOcInjectedKexts = AllocateZeroPool (sizeof (CHAR16*) * Config->Kernel.Add.Count);
  if (mOcInjectedKexts == NULL) {
    DEBUG ((DEBUG_WARN, "Failed to allocate injected kext name mappings\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Generate injected kext names and calculate directory size.
  //
  FileNameIndex = 0;
  DirectorySize = 0;
  for (Index = 0; Index < Config->Kernel.Add.Count; Index++) {
    Kext = Config->Kernel.Add.Values[Index];
    if (!Kext->Enabled || Kext->PlistDataSize == 0) {
      continue;
    }

    //
    // Generate next available filename.
    //
    mOcInjectedKexts[Index] = AllocatePool (BundleFileNameSize);
    if (mOcInjectedKexts[Index] == NULL) {
      DEBUG ((DEBUG_WARN, "Failed to allocate injected kext %u name mapping\n", Index));
      for (IndexClean = 0; IndexClean < Index; IndexClean++) {
        if (mOcInjectedKexts[IndexClean] != NULL) {
          FreePool (mOcInjectedKexts[IndexClean]);
        }
      }
      FreePool (mOcInjectedKexts);

      return EFI_OUT_OF_RESOURCES;
    }

    do {
      if (FileNameIndex == MAX_UINT32) {
        return EFI_DEVICE_ERROR;
      }

      BundleFileNameLength = UnicodeSPrint (mOcInjectedKexts[Index], BundleFileNameSize, L"Oc%8X.kext", FileNameIndex++);
      ASSERT (BundleFileNameLength == L_STR_LEN (L"OcXXXXXXXX.kext"));

      Status = (*File)->Open (*File, &NewFile, mOcInjectedKexts[Index], EFI_FILE_MODE_READ, 0);
      if (!EFI_ERROR (Status)) {
        NewFile->Close (NewFile);
      }
    } while (!EFI_ERROR (Status));

    DirectorySize += ALIGN_VALUE (SIZE_OF_EFI_FILE_INFO + BundleFileNameSize, OC_ALIGNOF (EFI_FILE_INFO));
  }

  //
  // Allocate directory buffer.
  //
  DirectoryBuffer = AllocateZeroPool (DirectorySize);
  if (DirectoryBuffer == NULL) {
    DEBUG ((DEBUG_WARN, "Failed to allocate directory buffer\n"));
    for (IndexClean = 0; IndexClean < Config->Kernel.Add.Count; IndexClean++) {
      if (mOcInjectedKexts[IndexClean] != NULL) {
        FreePool (mOcInjectedKexts[IndexClean]);
      }
    }
    FreePool (mOcInjectedKexts);

    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Build directory structure.
  //
  DirectoryOffset = 0;
  for (Index = 0; Index < Config->Kernel.Add.Count; Index++) {
    FileInfo = (EFI_FILE_INFO*)(DirectoryBuffer + DirectoryOffset); // Does this need overflow protection?

    CopyMem (FileInfo->FileName, mOcInjectedKexts[Index], BundleFileNameSize);
    FileInfo->Size = SIZE_OF_EFI_FILE_INFO + BundleFileNameSize;
    FileInfo->Attribute = EFI_FILE_READ_ONLY | EFI_FILE_DIRECTORY;
    FileInfo->FileSize = SIZE_OF_EFI_FILE_INFO + StrSize(L"Contents");
    FileInfo->PhysicalSize = FileInfo->FileSize;

    DirectoryOffset += ALIGN_VALUE (SIZE_OF_EFI_FILE_INFO + BundleFileNameSize, OC_ALIGNOF (EFI_FILE_INFO));
  }

  Status = CreateVirtualDirFileNameCopy (FileName, DirectoryBuffer, DirectorySize, NULL, *File, &VirtualFileHandle);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "Failed to virtualise dir file (%a)\n", FileName));
    FreePool (DirectoryBuffer);
    for (IndexClean = 0; IndexClean < Config->Kernel.Add.Count; IndexClean++) {
        if (mOcInjectedKexts[IndexClean] != NULL) {
          FreePool (mOcInjectedKexts[IndexClean]);
        }
      }
    FreePool (mOcInjectedKexts);

    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Return our virtual handle.
  //
  *File = VirtualFileHandle;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
OcKernelInjectExtensionsDir (
  IN  OC_GLOBAL_CONFIG  *Config,
  OUT EFI_FILE_PROTOCOL  **File,
  IN  CHAR16             *FileName
  ) 
{
  EFI_STATUS          Status;
  EFI_FILE_PROTOCOL   *VirtualFileHandle;
  CHAR16              *RealFileName;
  UINT8               *Buffer;
  UINTN               BufferSize;
  UINT32              Index;
  OC_KERNEL_ADD_ENTRY *Kext;

  CHAR16              *BundleName;
  CHAR16              *KextExtension;
  CHAR16              *BundlePath;
  UINTN               BundleLength;

  EFI_FILE_INFO       *FileInfo;
  UINTN               ContentsInfoEntrySize;
  UINTN               ContentsMacOsEntrySize;

  //
  // Only process injected extensions.
  //
  BundleName = StrStr (FileName, L"Oc");
  if (BundleName == NULL) {
    return EFI_NOT_FOUND;
  }
  KextExtension = StrStr (BundleName, L".kext");
  if (KextExtension == NULL) {
    return EFI_NOT_FOUND;
  }
  BundlePath = KextExtension + L_STR_LEN (L".kext");
  BundleLength = BundlePath - BundleName;

  //
  // Ensure our mapping array is valid.
  //
  if (mOcInjectedKexts == NULL) {
    return EFI_NOT_FOUND;
  }

  //
  // Find matching kext.
  //
  for (Index = 0; Index < Config->Kernel.Add.Count; ++Index) {
    if (StrnCmp (BundleName, mOcInjectedKexts[Index], BundleLength) == 0) {
      Kext = Config->Kernel.Add.Values[Index];
      DEBUG ((DEBUG_INFO, "Matched kext %u for %s\n", Index, FileName));

      //
      // Contents is being requested.
      //
      if (StrCmp (BundlePath, L"\\Contents") == 0) {
        //
        // Calculate and allocate entry for Contents.
        //
        ContentsInfoEntrySize = SIZE_OF_EFI_FILE_INFO + L_STR_SIZE (L"Info.plist");
        ContentsMacOsEntrySize = SIZE_OF_EFI_FILE_INFO + L_STR_SIZE (L"MacOS");
        BufferSize = ALIGN_VALUE (ContentsInfoEntrySize, OC_ALIGNOF (EFI_FILE_INFO)) + ContentsMacOsEntrySize;
        Buffer = AllocateZeroPool (BufferSize);
        if (Buffer == NULL) {
          return EFI_OUT_OF_RESOURCES;
        }

        //
        // Create Info.plist directory entry.
        //
        FileInfo = (EFI_FILE_INFO*)Buffer;
        FileInfo->Size = ContentsInfoEntrySize;
        CopyMem (FileInfo->FileName, L"Info.plist", L_STR_SIZE (L"Info.plist"));
        FileInfo->Attribute = EFI_FILE_READ_ONLY;
        FileInfo->PhysicalSize = FileInfo->FileSize = Kext->PlistDataSize;

        //
        // Create MacOS directory entry.
        //
        FileInfo = (EFI_FILE_INFO*)(Buffer + ALIGN_VALUE (ContentsInfoEntrySize, OC_ALIGNOF (EFI_FILE_INFO)));
        FileInfo->Size = ContentsMacOsEntrySize;
        CopyMem (FileInfo->FileName, L"MacOS", L_STR_SIZE (L"MacOS"));
        FileInfo->Attribute = EFI_FILE_READ_ONLY | EFI_FILE_DIRECTORY;
        FileInfo->PhysicalSize = FileInfo->FileSize = SIZE_OF_EFI_FILE_INFO + L_STR_SIZE (L"BINARY");

        //
        // Create virtual Contents directory.
        //
        Status = CreateVirtualDirFileNameCopy (L"Contents", Buffer, BufferSize, NULL, NULL, &VirtualFileHandle);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_WARN, "Failed to virtualise Contents directory (%a)\n", FileName));
          FreePool (Buffer);
          return EFI_OUT_OF_RESOURCES;
        }
      } else {
        //
        // Contents/Info.plist is being requested.
        //
        if (StrCmp (BundlePath, L"\\Contents\\Info.plist") == 0) {
          // Get Info.plist.
          RealFileName = L"Info.plist";
          BufferSize = Kext->PlistDataSize;
          Buffer = AllocateCopyPool (BufferSize, Kext->PlistData);
          if (Buffer == NULL) {
            return EFI_OUT_OF_RESOURCES;
          }

        //
        // Contents/MacOS/BINARY is being requested.
        // It should be safe to assume there will only be one binary ever requested per kext?
        //
        } else if (StrStr (BundlePath, L"\\Contents\\MacOS\\") != NULL) {
          RealFileName = L"BINARY";
          BufferSize = Kext->ImageDataSize;
          Buffer = AllocateCopyPool (BufferSize, Kext->ImageData);
          if (Buffer == NULL) {
            return EFI_OUT_OF_RESOURCES;
          }
        } else {
          return EFI_NOT_FOUND;
        }

        //
        // Create virtual file.
        //
        Status = CreateVirtualFileFileNameCopy (RealFileName, Buffer, BufferSize, NULL, &VirtualFileHandle);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_WARN, "Failed to virtualise file (%a)\n", FileName));
          FreePool (Buffer);
          return EFI_OUT_OF_RESOURCES;
        }
      }

      //
      // Return our handle.
      //
      *File = VirtualFileHandle;
      return EFI_SUCCESS;
    }
  }

  // No matching kext.
  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
OcKernelInitExtensionsPatcher (
  IN EFI_FILE_PROTOCOL    *File,
  OUT UINT8               **Buffer,
  OUT UINT32              *BufferSize,
  IN OUT PATCHER_CONTEXT  *Patcher
  )
{
  EFI_STATUS Status;
  UINT8 *FileBuffer;
  UINT32 FileSize;
  PATCHER_CONTEXT FilePatcher;

  ASSERT (Buffer != NULL);
  ASSERT (BufferSize != NULL);
  ASSERT (Patcher != NULL);

  if (*Buffer != NULL) {
    return EFI_SUCCESS;
  }

  Status = AllocateCopyFileData (File, &FileBuffer, &FileSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = PatcherInitContextFromBuffer (&FilePatcher, FileBuffer, FileSize);
  if (EFI_ERROR (Status)) {
    FreePool (FileBuffer);
    return Status;
  }

  *Buffer = FileBuffer;
  *BufferSize = FileSize;
  CopyMem (Patcher, &FilePatcher, sizeof (PATCHER_CONTEXT));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
OcKernelProcessExtensionsDir (
  IN  OC_GLOBAL_CONFIG     *Config,
  IN OUT EFI_FILE_PROTOCOL **File,
  IN  CHAR16               *FileName
  ) 
{
  EFI_STATUS             Status;
  CHAR16                 *ResultStr;
  EFI_FILE_PROTOCOL      *VirtualFileHandle;
  EFI_TIME               ModificationTime;

  UINT32                 Index;
  OC_KERNEL_PATCH_ENTRY  *UserPatch;
  OC_KERNEL_BLOCK_ENTRY  *UserBlock;
  CONST CHAR8            *Target;
  PATCHER_CONTEXT        Patcher;

  UINT8               *Buffer;
  UINT32              BufferSize;

  XML_DOCUMENT        *PlistDoc;
  XML_NODE            *PlistRoot;
  UINT32              PlistChildCount;
  XML_NODE            *PlistChildKey;
  XML_NODE            *PlistChildValue;
  CONST CHAR8         *PlistChildKeyStr;
  UINT32              PlistChildStrSize;

  CHAR8               *BundleName;
  CHAR8               *BinaryName;


  STATIC CHAR16       *AppleIntelCpuPmBinaryName = NULL;

  Buffer = NULL;

  //
  // Parse Info.plist
  //
  if ((ResultStr = StrStr (FileName, L"Info.plist")) != NULL
    && StrLen (ResultStr) == L_STR_LEN (L"Info.plist")) {
    //
    // Read plist data.
    //
    Status = AllocateCopyFileData (*File, &Buffer, &BufferSize);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    //
    // Initialize plist XML.
    //
    PlistDoc = XmlDocumentParse ((CHAR8*)Buffer, BufferSize, FALSE);
    if (PlistDoc == NULL) {
      FreePool (Buffer);
      return EFI_DEVICE_ERROR;
    }
    PlistRoot = PlistDocumentRoot (PlistDoc);
    if (PlistRoot == NULL) {
      FreePool (PlistDoc);
      FreePool (Buffer);
      return EFI_DEVICE_ERROR;
    }

    //
    // Iterate through children and pick out bundle ID and executable name.
    //
    BundleName = NULL;
    BinaryName = NULL;
    PlistChildCount = PlistDictChildren (PlistRoot);
    for (UINT32 i = 0; i < PlistChildCount; i++) {
      PlistChildKey = PlistDictChild (PlistRoot, i, &PlistChildValue);
      PlistChildKeyStr = PlistKeyValue (PlistChildKey);
      if (PlistChildKeyStr != NULL) {
        //
        // Get bundle name.
        //
        if (AsciiStrCmp (PlistChildKeyStr, "CFBundleIdentifier") == 0) {
          if (!PlistStringSize (PlistChildValue, &PlistChildStrSize)) {
            if (BinaryName != NULL) {
              FreePool (BinaryName);
            }
            FreePool (PlistDoc);
            FreePool (Buffer);

            //
            // Returning an error here would prevent the kext from being properly loaded.
            // If this value is not a string it only prevents patching.
            //
            return EFI_SUCCESS;
          }

          BundleName = AllocateZeroPool (PlistChildStrSize);
          if (BundleName == NULL) {
            if (BinaryName != NULL) {
              FreePool (BinaryName);
            }
            FreePool (PlistDoc);
            FreePool (Buffer);
            return EFI_OUT_OF_RESOURCES;
          }
          if (!PlistStringValue (PlistChildValue, BundleName, &PlistChildStrSize)) {
            if (BinaryName != NULL) {
              FreePool (BinaryName);
            }
            FreePool (BundleName);
            FreePool (PlistDoc);
            FreePool (Buffer);
            return EFI_DEVICE_ERROR;
          }
        //
        // Get binary name.
        //
        } else if (AsciiStrCmp (PlistChildKeyStr, "CFBundleExecutable") == 0) {
          if (!PlistStringSize (PlistChildValue, &PlistChildStrSize)) {
            if (BundleName != NULL) {
              FreePool (BundleName);
            }
            FreePool (PlistDoc);
            FreePool (Buffer);

            //
            // Returning an error here would prevent the kext from being properly loaded.
            // If this value is not a string it only prevents patching.
            //
            return EFI_SUCCESS;
          }

          BinaryName = AllocateZeroPool (PlistChildStrSize);
          if (BinaryName == NULL) {
            if (BundleName != NULL) {
              FreePool (BundleName);
            }
            FreePool (PlistDoc);
            FreePool (Buffer);
            return EFI_OUT_OF_RESOURCES;
          }
          if (!PlistStringValue (PlistChildValue, BinaryName, &PlistChildStrSize)) {
            if (BundleName != NULL) {
              FreePool (BundleName);
            }
            FreePool (BinaryName);
            FreePool (PlistDoc);
            FreePool (Buffer);
            return EFI_DEVICE_ERROR;
          }
        }
      }

      //
      // Can finish early if both strings are found already.
      //
      if (BundleName != NULL && BinaryName != NULL) {
        break;
      }
    }
    FreePool (PlistDoc);
    FreePool (Buffer);

    //
    // If one or both values were not found, this simply prevents patching and is not an error.
    // Some codeless kexts exist in /S/L/E.
    //
    if (BundleName == NULL || BinaryName == NULL) {
      if (BundleName != NULL) {
        FreePool (BundleName);
      }
      if (BinaryName != NULL) {
        FreePool (BinaryName);
      }
      return EFI_SUCCESS;
    }

    //
    // Allocate array for storing kext binaries for kexts to patch and block.
    //
    if (mOcPatchedKexts == NULL) {
      mOcPatchedKexts = AllocateZeroPool (Config->Kernel.Patch.Count * sizeof (CHAR16*));
      if (mOcPatchedKexts == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
    }
    if (mOcBlockedKexts == NULL) {
      mOcBlockedKexts = AllocateZeroPool (Config->Kernel.Block.Count * sizeof (CHAR16*));
      if (mOcBlockedKexts == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
    }

    //
    // Store binary name for patching later on.
    //
    for (Index = 0; Index < Config->Kernel.Patch.Count; Index++) {
      UserPatch = Config->Kernel.Patch.Values[Index];
      Target    = OC_BLOB_GET (&UserPatch->Identifier);

      if (!UserPatch->Enabled || (AsciiStrCmp (Target, "kernel") == 0)) {
        continue;
      }

      if (AsciiStrCmp (Target, BundleName) == 0) {
        mOcPatchedKexts[Index] = AsciiStrCopyToUnicode (BinaryName, 0);
        if (mOcPatchedKexts[Index] == NULL) {
          FreePool (BundleName);
          FreePool (BinaryName);
          return EFI_OUT_OF_RESOURCES;
        }
        DEBUG ((DEBUG_INFO, "OC: Stored patch request %s for kext %u\n", mOcPatchedKexts[Index], Index));
      }
    }

    //
    // Store binary names for built-in patches.
    //
    if (Config->Kernel.Quirks.AppleCpuPmCfgLock 
    && AsciiStrCmp (BundleName, "com.apple.driver.AppleIntelCPUPowerManagement") == 0) {
      AppleIntelCpuPmBinaryName = AsciiStrCopyToUnicode (BinaryName, 0);
    }

    //
    // Store binary name for blocking later on.
    //
    for (Index = 0; Index < Config->Kernel.Block.Count; Index++) {
      UserBlock = Config->Kernel.Block.Values[Index];
      Target    = OC_BLOB_GET (&UserBlock->Identifier);

      if (!UserBlock->Enabled) {
        continue;
      }

      if (AsciiStrCmp (Target, BundleName) == 0) {
        mOcBlockedKexts[Index] = AsciiStrCopyToUnicode (BinaryName, 0);
        if (mOcBlockedKexts[Index] == NULL) {
          FreePool (BundleName);
          FreePool (BinaryName);
          return EFI_OUT_OF_RESOURCES;
        }
        DEBUG ((DEBUG_INFO, "OC: Stored block request %s for kext %u\n", mOcBlockedKexts[Index], Index));
      }
    }

    FreePool (BundleName);
    FreePool (BinaryName);

  //
  // Patch and/or block binary.
  //
  } else if ((ResultStr = StrStr (FileName, L"MacOS\\")) != NULL) {
    if (StrLen (ResultStr) == L_STR_LEN (L"MacOS\\")) {
      return EFI_DEVICE_ERROR;
    }
    ResultStr += L_STR_LEN (L"MacOS\\");

    //
    // Process patches.
    //
    for (Index = 0; Index < Config->Kernel.Patch.Count; Index++) {
      UserPatch = Config->Kernel.Patch.Values[Index];
      Target    = OC_BLOB_GET (&UserPatch->Identifier);

      if (mOcPatchedKexts[Index] == NULL) {
        continue;
      }

      if (StrCmp (ResultStr, mOcPatchedKexts[Index]) == 0) {
        Status = OcKernelInitExtensionsPatcher (*File, &Buffer, &BufferSize, &Patcher);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_WARN, "OC: Patcher %a init failure - %r\n", Target, Status));
          break;
        }

        Status = OcKernelApplyPatch (&Patcher, UserPatch);
        DEBUG ((
          EFI_ERROR (Status) ? DEBUG_WARN : DEBUG_INFO,
          "OC: Kernel patcher result %u for %a - %r\n",
          Index,
          Target,
          Status
          ));
      }
    }

    //
    // Process built-in patches.
    //
    if (AppleIntelCpuPmBinaryName != NULL && StrCmp (ResultStr, AppleIntelCpuPmBinaryName) == 0) {
        Status = OcKernelInitExtensionsPatcher (*File, &Buffer, &BufferSize, &Patcher);
        if (!EFI_ERROR (Status)) {
          PatchAppleCpuPmCfgLock (&Patcher);
        }
    }

    //
    // Process blocks. TODO: Currently fails with EFI_UNSUPPORTED.
    //
    for (Index = 0; Index < Config->Kernel.Block.Count; Index++) {
      UserBlock = Config->Kernel.Block.Values[Index];
      Target    = OC_BLOB_GET (&UserBlock->Identifier);

      if (mOcBlockedKexts[Index] == NULL) {
        continue;
      }

      if (StrCmp (ResultStr, mOcBlockedKexts[Index]) == 0) {
        Status = OcKernelInitExtensionsPatcher (*File, &Buffer, &BufferSize, &Patcher);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_WARN, "OC: Patcher %a init failure - %r\n", Target, Status));
          break;
        }

        //
        // Block kext.
        //
        Status = PatcherBlockKext (&Patcher);
        DEBUG ((
          EFI_ERROR (Status) ? DEBUG_WARN : DEBUG_INFO,
          "OC: Blocker %a - %r\n",
          Target,
          Status
          ));
      }
    }

    //
    // Create virtual file if binary was modified.
    //
    if (Buffer != NULL) {
      Status = GetFileModifcationTime (*File, &ModificationTime);
      if (EFI_ERROR (Status)) {
        ZeroMem (&ModificationTime, sizeof (ModificationTime));
      }

      (*File)->Close(*File);

      //
      // This was our file, yet firmware is dying.
      //
      Status = CreateVirtualFileFileNameCopy (FileName, Buffer, BufferSize, &ModificationTime, &VirtualFileHandle);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "Failed to virtualise kext file (%a)\n", FileName));
        FreePool (Buffer);
        return EFI_OUT_OF_RESOURCES;
      }

      //
      // Return our handle.
      //
      *File = VirtualFileHandle;
    }
  }
  
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
OcKernelFileOpen (
  IN  EFI_FILE_PROTOCOL       *This,
  OUT EFI_FILE_PROTOCOL       **NewHandle,
  IN  CHAR16                  *FileName,
  IN  UINT64                  OpenMode,
  IN  UINT64                  Attributes
  )
{
  EFI_STATUS         Status;
  UINT8              *Kernel;
  UINT32             KernelSize;
  UINT32             AllocatedSize;
  EFI_FILE_PROTOCOL  *VirtualFileHandle;
  EFI_STATUS         PrelinkedStatus;
  EFI_TIME           ModificationTime;
  CHAR8              DarwinVersion[16];

  //
  // Hook injected OcXXXXXXXX.kext reads from /S/L/E.
  //
  if (OpenMode == EFI_FILE_MODE_READ
    && StrnCmp (FileName, L"System\\Library\\Extensions\\Oc", L_STR_LEN (L"System\\Library\\Extensions\\Oc")) == 0) {
    Status = OcKernelInjectExtensionsDir (mOcConfiguration, NewHandle, FileName);
    DEBUG ((
      DEBUG_INFO,
      "Opening injected file %s with %u mode gave - %r\n",
      FileName,
      (UINT32) OpenMode,
      Status
      ));

    return Status;
  }


  Status = This->Open (This, NewHandle, FileName, OpenMode, Attributes);

  DEBUG ((
    DEBUG_VERBOSE,
    "Opening file %s with %u mode gave - %r\n",
    FileName,
    (UINT32) OpenMode,
    Status
    ));

  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // 
  //

  // Patch cppm
 /* if (OpenMode == EFI_FILE_MODE_READ
    && StrCmp (FileName, L"System\\Library\\Extensions\\AppleIntelCPUPowerManagement.kext\\Contents\\MacOS\\AppleIntelCPUPowerManagement") == 0) {
    DEBUG ((DEBUG_INFO, "patch cpupm\n"));
    GetFileSize (*NewHandle, &KernelSize);
    Kernel = AllocatePool (KernelSize);
    GetFileData (*NewHandle, 0, KernelSize, Kernel);

    PATCHER_CONTEXT pContext;
    PatcherInitContextFromBuffer (&pContext, Kernel, KernelSize);
    PatchAppleCpuPmCfgLock (&pContext);

      Status = GetFileModifcationTime (*NewHandle, &ModificationTime);
      if (EFI_ERROR (Status)) {
        ZeroMem (&ModificationTime, sizeof (ModificationTime));
      }

      (*NewHandle)->Close(*NewHandle);

      //
      // This was our file, yet firmware is dying.
      //
      Status = CreateVirtualFileFileNameCopy (FileName, Kernel, KernelSize, &ModificationTime, &VirtualFileHandle);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "Failed to virtualise kernel file (%a)\n", FileName));
        FreePool (Kernel);
        return EFI_OUT_OF_RESOURCES;
      }

      //
      // Return our handle.
      //
      *NewHandle = VirtualFileHandle;
      return EFI_SUCCESS;

    return EFI_SUCCESS;


  }*/


  //
  // boot.efi uses /S/L/K/kernel as is to determine valid filesystem.
  // Just skip it to speedup the boot process.
  // On 10.9 mach_kernel is loaded for manual linking aferwards, so we cannot skip it.
  //
  if (OpenMode == EFI_FILE_MODE_READ
    && StrStr (FileName, L"kernel") != NULL
    && StrCmp (FileName, L"System\\Library\\Kernels\\kernel") != 0) {

    DEBUG ((DEBUG_INFO, "Trying XNU hook on %s\n", FileName));
    Status = ReadAppleKernel (
      *NewHandle,
      &Kernel,
      &KernelSize,
      &AllocatedSize,
      OcKernelLoadKextsAndReserve (mOcStorage, mOcConfiguration)
      );
    DEBUG ((DEBUG_INFO, "Result of XNU hook on %s is %r\n", FileName, Status));

    //
    // This is not Apple kernel, just return the original file.
    //
    if (!EFI_ERROR (Status)) {
      OcKernelReadDarwinVersion (Kernel, KernelSize, DarwinVersion, sizeof (DarwinVersion));
      OcKernelApplyPatches (mOcConfiguration, DarwinVersion, NULL, Kernel, KernelSize);

      PrelinkedStatus = OcKernelProcessPrelinked (
        mOcConfiguration,
        DarwinVersion,
        Kernel,
        &KernelSize,
        AllocatedSize
        );

      DEBUG ((DEBUG_INFO, "Prelinked status - %r\n", PrelinkedStatus));

      Status = GetFileModifcationTime (*NewHandle, &ModificationTime);
      if (EFI_ERROR (Status)) {
        ZeroMem (&ModificationTime, sizeof (ModificationTime));
      }

      (*NewHandle)->Close(*NewHandle);

      //
      // This was our file, yet firmware is dying.
      //
      Status = CreateVirtualFileFileNameCopy (FileName, Kernel, KernelSize, &ModificationTime, &VirtualFileHandle);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "Failed to virtualise kernel file (%a)\n", FileName));
        FreePool (Kernel);
        return EFI_OUT_OF_RESOURCES;
      }

      //
      // Return our handle.
      //
      *NewHandle = VirtualFileHandle;
      return EFI_SUCCESS;
    }
  }

  //
  // Hook /S/L/E and provide virtual directory overlay for injected kexts.
  //
  if (OpenMode == EFI_FILE_MODE_READ
    && StrCmp (FileName, L"System\\Library\\Extensions") == 0) {
    DEBUG ((DEBUG_INFO, "Hooking into /S/L/E directory\n"));

    //
    // Load kexts into memory and build directory.
    //
    OcKernelLoadKextsAndReserve (mOcStorage, mOcConfiguration);
    return OcKernelBuildExtensionsDir (mOcConfiguration, NewHandle, FileName);
  }

  //
  // Hook /S/L/E kext binary reads for pre-existing kexts.
  // This allows for patching/blocking.
  //
  if (OpenMode == EFI_FILE_MODE_READ
    && StrnCmp (FileName, L"System\\Library\\Extensions\\", L_STR_LEN (L"System\\Library\\Extensions\\")) == 0) {
    return OcKernelProcessExtensionsDir (mOcConfiguration, NewHandle, FileName);
  }

  //
  // We recurse the filtering to additionally catch com.apple.boot.[RPS] directories.
  //
  return CreateRealFile (*NewHandle, OcKernelFileOpen, TRUE, NewHandle);
}

VOID
OcLoadKernelSupport (
  IN OC_STORAGE_CONTEXT  *Storage,
  IN OC_GLOBAL_CONFIG    *Config,
  IN OC_CPU_INFO         *CpuInfo
  )
{
  EFI_STATUS  Status;

  Status = EnableVirtualFs (gBS, OcKernelFileOpen);

  if (!EFI_ERROR (Status)) {
    mOcStorage       = Storage;
    mOcConfiguration = Config;
    mOcCpuInfo       = CpuInfo;
  } else {
    DEBUG ((DEBUG_ERROR, "OC: Failed to enable vfs - %r\n", Status));
  }
}

VOID
OcUnloadKernelSupport (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mOcStorage != NULL) {
    Status = DisableVirtualFs (gBS);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "OC: Failed to disable vfs - %r\n", Status));
    }
    mOcStorage       = NULL;
    mOcConfiguration = NULL;
  }
}
