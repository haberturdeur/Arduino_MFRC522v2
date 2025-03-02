/* SPDX-License-Identifier: LGPL-2.1 */
#pragma once

#include <MFRC522v2.h>
#include <MFRC522Debug.h>

#include <iostream>
#include <cstdint>

class MFRC522Hack {
private:
  using StatusCode = MFRC522Constants::StatusCode;
  using PICC_Command = MFRC522Constants::PICC_Command;
  MFRC522 &_device;
  bool _logErrors;
  std::ostream *_logStream;

public:
  MFRC522Hack(MFRC522 &device, const bool logErrors, std::ostream *logStream = nullptr) : _device(device), _logStream(logStream) {
    _logErrors = logErrors && (logStream != nullptr);
  };
  
  bool MIFARE_OpenUidBackdoor(void) const;
  
  bool MIFARE_SetUid(const std::uint8_t *const newUid, const std::uint8_t uidSize, MFRC522::MIFARE_Key &key, bool withBackdoor) const;
  
  bool MIFARE_UnbrickUidSector(void) const;
};
