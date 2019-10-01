/** @file
  Copyright (C) 2019, Goldfish64. All rights reserved.

  All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef OPEN_CORE_KERNEL_H
#define OPEN_CORE_KERNEL_H

#include <Library/OcAppleKernelLib.h>
#include <Library/OcConfigurationLib.h>
#include <Library/OcCpuLib.h>
#include <Library/OcCryptoLib.h>
#include <Library/OcGuardLib.h>
#include <Library/OcStringLib.h>
#include <Library/OcStorageLib.h>


EFI_STATUS
OcKernelBuildExtensionsDir (
  IN     OC_GLOBAL_CONFIG  *Config,
  IN OUT EFI_FILE_PROTOCOL  **File,
  IN     CHAR16             *FileName
  );

EFI_STATUS
OcKernelInjectExtensionsDir (
  IN  OC_GLOBAL_CONFIG  *Config,
  OUT EFI_FILE_PROTOCOL  **File,
  IN  CHAR16             *FileName
  );

EFI_STATUS
OcKernelProcessExtensionsDir (
  IN  OC_GLOBAL_CONFIG     *Config,
  IN OUT EFI_FILE_PROTOCOL **File,
  IN  CHAR16               *FileName
  );

RETURN_STATUS
OcKernelApplyPatch (
  IN PATCHER_CONTEXT       *Patcher,
  IN OC_KERNEL_PATCH_ENTRY *UserPatch
  );

#endif
