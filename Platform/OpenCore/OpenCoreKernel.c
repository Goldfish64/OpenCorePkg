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
#include <OpenCoreKernel.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcAppleKernelLib.h>
#include <Library/OcMiscLib.h>
#include <Library/OcStringLib.h>
#include <Library/OcVirtualFsLib.h>
#include <Library/OcCompressionLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>


#include <IndustryStandard/AppleFatBinaryImage.h>
#include <IndustryStandard/AppleMkext.h>

STATIC OC_STORAGE_CONTEXT  *mOcStorage;
STATIC OC_GLOBAL_CONFIG    *mOcConfiguration;
STATIC OC_CPU_INFO         *mOcCpuInfo;

STATIC
UINT32
OcParseDarwinVersion (
  IN  CONST CHAR8         *String
  )
{
  UINT32  Version;
  UINT32  Index;
  UINT32  Index2;

  if (*String == '\0' || *String < '0' || *String > '9') {
    return 0;
  }

  Version = 0;

  for (Index = 0; Index < 3; ++Index) {
    for (Index2 = 0; Index2 < 2; ++Index2) {
      Version *= 10;
      if (*String >= '0' && *String <= '9') {
        Version += *String++ - '0';
      } else if (*String != '.' && *String != '\0') {
        return 0;
      }
    }

    if (*String == '.') {
      ++String;
    }
  }

  return Version;
}

STATIC
BOOLEAN
OcMatchDarwinVersion (
  IN  UINT32  CurrentVersion,
  IN  UINT32  MinVersion,
  IN  UINT32  MaxVersion
  )
{
  //
  // Check against min <= curr <= max.
  // curr=0 -> curr=inf, max=0  -> max=inf
  //

  //
  // Replace max inf with max known version.
  //
  if (MaxVersion == 0) {
    MaxVersion = CurrentVersion;
  }

  //
  // Handle curr=inf <= max=inf(?) case.
  //
  if (CurrentVersion == 0) {
    return MaxVersion == 0;
  }

  //
  // Handle curr=num > max=num case.
  //
  if (CurrentVersion > MaxVersion) {
    return FALSE;
  }

  //
  // Handle min=num > curr=num case.
  //
  if (CurrentVersion < MinVersion) {
    return FALSE;
  }

  return TRUE;
}

STATIC
UINT32
OcKernelReadDarwinVersion (
  IN  CONST UINT8   *Kernel,
  IN  UINT32        KernelSize
  )
{
  INT32   Offset;
  UINT32  Index;
  CHAR8   DarwinVersion[32];
  CHAR8   DarwinVersionInteger;


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
    return 0;
  }

  Offset += L_STR_LEN ("Darwin Kernel Version ");

  for (Index = 0; Index < ARRAY_SIZE (DarwinVersion) - 1; ++Index, ++Offset) {
    if ((UINT32) Offset >= KernelSize || Kernel[Offset] == ':') {
      break;
    }
    DarwinVersion[Index] = (CHAR8) Kernel[Offset];
  }
  DarwinVersion[Index] = '\0';
  DarwinVersionInteger = (CHAR8) OcParseDarwinVersion (DarwinVersion);

  DEBUG ((
    DEBUG_INFO,
    "OC: Read kernel version %a (%u)\n",
    DarwinVersion,
    DarwinVersionInteger
    ));

  return DarwinVersionInteger;
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
  CHAR8                *Comment;
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
      Comment        = OC_BLOB_GET (&Kext->Comment);
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
        DEBUG ((
          DEBUG_ERROR,
          "OC: Plist %s is missing for kext %a (%a)\n",
          FullPath,
          BundlePath,
          Comment
          ));
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
          DEBUG ((
            DEBUG_ERROR,
            "OC: Image %s is missing for kext %a (%a)\n",
            FullPath,
            BundlePath,
            Comment
            ));
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
  IN     UINT32            DarwinVersion,
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
  CONST CHAR8            *Comment;
  UINT32                 MaxKernel;
  UINT32                 MinKernel;
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
    Comment   = OC_BLOB_GET (&UserPatch->Comment);

    if (!UserPatch->Enabled || (AsciiStrCmp (Target, "kernel") == 0) != IsKernelPatch) {
      continue;
    }

    MaxKernel   = OcParseDarwinVersion (OC_BLOB_GET (&UserPatch->MaxKernel));
    MinKernel   = OcParseDarwinVersion (OC_BLOB_GET (&UserPatch->MaxKernel));

    if (!OcMatchDarwinVersion (DarwinVersion, MinKernel, MaxKernel)) {
      DEBUG ((
        DEBUG_INFO,
        "OC: Kernel patcher skips %a (%a) patch at %u due to version %u <= %u <= %u",
        Target,
        Comment,
        Index,
        MinKernel,
        DarwinVersion,
        MaxKernel
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
        DEBUG ((DEBUG_WARN, "OC: Kernel patcher %a (%a) init failure - %r\n", Target, Comment, Status));
        continue;
      } else {
        DEBUG ((DEBUG_INFO, "OC: Kernel patcher %a (%a) init succeed\n", Target, Comment));
      }
    }

    Status = OcKernelApplyPatch (&Patcher, UserPatch);
    DEBUG ((
      EFI_ERROR (Status) ? DEBUG_WARN : DEBUG_INFO,
      "OC: Kernel patcher result %u for %a (%a) - %r\n",
      Index,
      Target,
      Comment,
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
  IN     UINT32            DarwinVersion,
  IN     PRELINKED_CONTEXT *Context
  )
{
  EFI_STATUS             Status;
  PATCHER_CONTEXT        Patcher;
  UINT32                 Index;
  OC_KERNEL_BLOCK_ENTRY  *Kext;
  CONST CHAR8            *Target;
  CONST CHAR8            *Comment;
  UINT32                 MaxKernel;
  UINT32                 MinKernel;

  for (Index = 0; Index < Config->Kernel.Block.Count; ++Index) {
    Kext    = Config->Kernel.Block.Values[Index];
    Target  = OC_BLOB_GET (&Kext->Identifier);
    Comment = OC_BLOB_GET (&Kext->Comment);

    if (!Kext->Enabled) {
      continue;
    }

    MaxKernel = OcParseDarwinVersion (OC_BLOB_GET (&Kext->MaxKernel));
    MinKernel = OcParseDarwinVersion (OC_BLOB_GET (&Kext->MaxKernel));

    if (!OcMatchDarwinVersion (DarwinVersion, MinKernel, MaxKernel)) {
      DEBUG ((
        DEBUG_INFO,
        "OC: Prelink blocker skips %a (%a) block at %u due to version %u <= %u <= %u",
        Target,
        Comment,
        Index,
        MinKernel,
        DarwinVersion,
        MaxKernel
        ));
      continue;
    }

    Status = PatcherInitContextFromPrelinked (
      &Patcher,
      Context,
      Target
      );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "OC: Prelink blocker %a (%a) init failure - %r\n", Target, Comment, Status));
      continue;
    }

    Status = PatcherBlockKext (&Patcher);

    DEBUG ((
      EFI_ERROR (Status) ? DEBUG_WARN : DEBUG_INFO,
      "OC: Prelink blocker %a (%a) - %r\n",
      Target,
      Comment,
      Status
      ));
  }
}

STATIC
EFI_STATUS
OcKernelProcessPrelinked (
  IN     OC_GLOBAL_CONFIG  *Config,
  IN     UINT32            DarwinVersion,
  IN OUT UINT8             *Kernel,
  IN     UINT32            *KernelSize,
  IN     UINT32            AllocatedSize
  )
{
  EFI_STATUS           Status;
  PRELINKED_CONTEXT    Context;
  CHAR8                *BundlePath;
  CHAR8                *ExecutablePath;
  CHAR8                *Comment;
  UINT32               Index;
  CHAR8                FullPath[128];
  OC_KERNEL_ADD_ENTRY  *Kext;
  UINT32               MaxKernel;
  UINT32               MinKernel;

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
        Comment     = OC_BLOB_GET (&Kext->Comment);
        MaxKernel   = OcParseDarwinVersion (OC_BLOB_GET (&Kext->MaxKernel));
        MinKernel   = OcParseDarwinVersion (OC_BLOB_GET (&Kext->MaxKernel));

        if (!OcMatchDarwinVersion (DarwinVersion, MinKernel, MaxKernel)) {
          DEBUG ((
            DEBUG_INFO,
            "OC: Prelink injection skips %a (%a) kext at %u due to version %u <= %u <= %u",
            BundlePath,
            Comment,
            Index,
            MinKernel,
            DarwinVersion,
            MaxKernel
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
          "OC: Prelink injection %a (%a) - %r\n",
          BundlePath,
          Comment,
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
VOID
OcReadMkext (
  IN  OC_GLOBAL_CONFIG  *Config,
  IN  CHAR16                  *FileName,
  IN OUT EFI_FILE_PROTOCOL  **File
) {
  // Read wntire file.
    EFI_TIME           ModificationTime;

  UINT32 BufferSize;
  UINT8 *Buffer;
  UINT32 AllocSize;  
  UINT32               Index;
  OC_KERNEL_ADD_ENTRY  *Kext;

  ReadAppleMkext (*File, &Buffer, &BufferSize, &AllocSize, OcKernelLoadKextsAndReserve (mOcStorage, mOcConfiguration));

  //AllocateCopyFileData (*File, &Buffer, &BufferSize);

  MKEXT_CONTEXT Context;
  RETURN_STATUS Status2 = MkextContextInit (&Context, Buffer, BufferSize, AllocSize);
  ASSERT (Status2 == RETURN_SUCCESS);


  for (Index = 0; Index < Config->Kernel.Add.Count; Index++) {
    Kext = Config->Kernel.Add.Values[Index];
    if (!Kext->Enabled || Kext->PlistDataSize == 0) {
      continue;
    }


    Status2 = MkextInjectKext (&Context, "/tmp/b.kext", Kext->PlistData, Kext->PlistDataSize, Kext->ImageData, Kext->ImageDataSize);
    ASSERT (Status2 == RETURN_SUCCESS);
  }

  Status2 = MkextInjectComplete (&Context);
  ASSERT (Status2 == RETURN_SUCCESS);

        EFI_STATUS Status = GetFileModifcationTime (*File, &ModificationTime);
      if (EFI_ERROR (Status)) {
        ZeroMem (&ModificationTime, sizeof (ModificationTime));
      }

(*File)->Close(*File);

    //
  // Create virtual file.
  //
  Status = CreateVirtualFileFileNameCopy (FileName, Buffer, Context.MkextSize, &ModificationTime, File);
  if (EFI_ERROR (Status)) {
   // DEBUG ((DEBUG_WARN, "Failed to virtualise file (%a)\n", FileName));
    FreePool (Buffer);
   // return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((DEBUG_INFO, "Done with mkext\n"));
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
  UINT32             DarwinVersion;

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
      DarwinVersion = OcKernelReadDarwinVersion (Kernel, KernelSize);
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
    && StrCmp (FileName, L"System\\Library\\Extensions2") == 0) {
    DEBUG ((DEBUG_INFO, "OC: Hooking into /S/L/E directory\n"));

    //
    // Load kexts into memory and build directory.
    //
    OcKernelLoadKextsAndReserve (mOcStorage, mOcConfiguration);
    return OcKernelBuildExtensionsDir (mOcConfiguration, NewHandle, FileName);
  }

  if (OpenMode == EFI_FILE_MODE_READ
    && StrCmp (FileName, L"System\\Library\\Extensions") == 0) {
    DEBUG ((DEBUG_INFO, "OC: Passing into /S/L/E directory\n"));
  }

  //
  // Hook /S/L/E kext binary reads for pre-existing kexts.
  // This allows for patching/blocking.
  //
  if (OpenMode == EFI_FILE_MODE_READ
    && StrnCmp (FileName, L"System\\Library\\Extensions2\\", L_STR_LEN (L"System\\Library\\Extensions2\\")) == 0) {
    return OcKernelProcessExtensionsDir (mOcConfiguration, NewHandle, FileName);
  }

  if (OpenMode == EFI_FILE_MODE_READ
    && StrStr (FileName, L"Extensions.mkext") != NULL) {
    DEBUG ((DEBUG_INFO, "OC: Hooking mkext: %s\n", FileName));
    OcReadMkext (mOcConfiguration, FileName, NewHandle);
    return EFI_SUCCESS;
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
