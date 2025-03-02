#include "MFRC522Hack.h"

bool MFRC522Hack::MIFARE_OpenUidBackdoor(void) const {
  // Magic sequence described in the comments:
  _device.PICC_HaltA(); // 50 00 57 CD

  uint8_t cmd       = 0x40;
  uint8_t validBits = 7;
  uint8_t response[32] = {0};
  uint8_t received  = sizeof(response);

  StatusCode status = _device.PCD_TransceiveData(
                            &cmd,
                            (uint8_t)1,
                            response,
                            &received,
                            &validBits,
                            (uint8_t)0,
                            false
                      ); // 40
  if (status != StatusCode::STATUS_OK) {
    if (_logErrors && _logStream) {
      *_logStream << "Card did not respond to 0x40 after HALT command. "
                  << "Are you sure it is a UID changeable one?" << std::endl;
      *_logStream << "Error name: "
                  << MFRC522Debug::GetStatusCodeName(status) << std::endl;
    }
    return false;
  }
  if (received != 1 || response[0] != 0x0A) {
    if (_logErrors && _logStream) {
      *_logStream << "Got bad response on backdoor 0x40 command: "
                  << "0x" << std::hex << (int)response[0] << std::dec
                  << " (" << (int)validBits << " valid bits)" << std::endl;
    }
    return false;
  }

  cmd       = 0x43;
  validBits = 8;
  status    = _device.PCD_TransceiveData(
                  &cmd,
                  (uint8_t)1,
                  response,
                  &received,
                  &validBits,
                  (uint8_t)0,
                  false
              ); // 43
  if (status != StatusCode::STATUS_OK) {
    if (_logErrors && _logStream) {
      *_logStream << "Error in communication at command 0x43, "
                  << "after successfully executing 0x40" << std::endl;
      *_logStream << "Error name: "
                  << MFRC522Debug::GetStatusCodeName(status) << std::endl;
    }
    return false;
  }
  if (received != 1 || response[0] != 0x0A) {
    if (_logErrors && _logStream) {
      *_logStream << "Got bad response on backdoor 0x43 command: "
                  << "0x" << std::hex << (int)response[0] << std::dec
                  << " (" << (int)validBits << " valid bits)" << std::endl;
    }
    return false;
  }

  // Success: you can now write to sector 0 without authenticating
  return true;
}

bool MFRC522Hack::MIFARE_SetUid(const uint8_t *const newUid,
                                const uint8_t uidSize,
                                MFRC522::MIFARE_Key &key,
                                const bool withBackdoor) const
{
  // UID + BCC byte cannot exceed 16
  if (!newUid || (uidSize == 0) || (uidSize > 15)) {
    if (_logErrors && _logStream) {
      *_logStream << "New UID buffer empty, size 0, or size > 15 given" << std::endl;
    }
    return false;
  }

  // Authenticate using KEY A
  StatusCode status = _device.PCD_Authenticate(
                          PICC_Command::PICC_CMD_MF_AUTH_KEY_A,
                          (uint8_t)1,
                          &key,
                          &(_device.uid)
                      );
  if (status != StatusCode::STATUS_OK) {
    if (status == StatusCode::STATUS_TIMEOUT) {
      // Possibly no card selected yet, try selecting one
      if (!_device.PICC_IsNewCardPresent() || !_device.PICC_ReadCardSerial()) {
        if (_logErrors && _logStream) {
          *_logStream << "No card was previously selected, and none are available. "
                      << "Failed to set UID." << std::endl;
        }
        return false;
      }
      // Try again
      status = _device.PCD_Authenticate(
                   PICC_Command::PICC_CMD_MF_AUTH_KEY_A,
                   (uint8_t)1,
                   &key,
                   &(_device.uid)
                 );
      if (status != StatusCode::STATUS_OK) {
        if (_logErrors && _logStream) {
          *_logStream << "Failed to authenticate to card for reading, could not set UID: "
                      << MFRC522Debug::GetStatusCodeName(status) << std::endl;
        }
        return false;
      }
    } else {
      if (_logErrors && _logStream) {
        *_logStream << "PCD_Authenticate() failed: "
                    << MFRC522Debug::GetStatusCodeName(status) << std::endl;
      }
      return false;
    }
  }

  // Read block 0
  uint8_t block0_buffer[18];
  uint8_t byteCount = sizeof(block0_buffer);

  status = _device.MIFARE_Read((uint8_t)0, block0_buffer, &byteCount);
  if (status != StatusCode::STATUS_OK) {
    if (_logErrors && _logStream) {
      *_logStream << "MIFARE_Read() failed: "
                  << MFRC522Debug::GetStatusCodeName(status) << std::endl
                  << "Are you sure your KEY A for sector 0 is correct?" << std::endl;
    }
    return false;
  }

  // Overwrite the UID part in block 0; calculate BCC
  uint8_t bcc = 0;
  for (uint8_t i = 0; i < uidSize; i++) {
    block0_buffer[i] = newUid[i];
    bcc ^= newUid[i];
  }
  block0_buffer[uidSize] = bcc;

  // If we need the “backdoor,” stop encrypted traffic and call MIFARE_OpenUidBackdoor
  if (withBackdoor) {
    _device.PCD_StopCrypto1();
    if (!MIFARE_OpenUidBackdoor()) {
      if (_logErrors && _logStream) {
        *_logStream << "Activating the UID backdoor failed." << std::endl;
      }
      return false;
    }
  }

  // Write modified block 0 back to card
  status = _device.MIFARE_Write((uint8_t)0, block0_buffer, (uint8_t)16);
  if (status != StatusCode::STATUS_OK) {
    if (_logErrors && _logStream) {
      *_logStream << "MIFARE_Write() failed: "
                  << MFRC522Debug::GetStatusCodeName(status) << std::endl;
    }
    return false;
  }

  // Wake the card up again if we used the backdoor
  if (withBackdoor) {
    uint8_t atqa_answer[2];
    uint8_t atqa_size = 2;
    _device.PICC_WakeupA(atqa_answer, &atqa_size);
  }
  return true;
}

bool MFRC522Hack::MIFARE_UnbrickUidSector(void) const {
  // Attempt to open the UID backdoor
  MIFARE_OpenUidBackdoor();

  uint8_t block0_buffer[] = {
    0x01, 0x02, 0x03, 0x04, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
  };

  // Write modified block 0 back to card.
  StatusCode status = _device.MIFARE_Write((uint8_t)0, block0_buffer, (uint8_t)16);
  if (status != StatusCode::STATUS_OK) {
    if (_logErrors && _logStream) {
      *_logStream << "MIFARE_Write() failed: "
                  << MFRC522Debug::GetStatusCodeName(status) << std::endl;
    }
    return false;
  }
  return true;
}
