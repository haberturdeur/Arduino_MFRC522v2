/* SPDX-License-Identifier: LGPL-2.1 */
#include "MFRC522Debug.h"
#include <string_view>
#include <iostream>
#include <iomanip>
/**
 * Returns a __FlashStringHelper pointer to the PICC type name.
 * 
 * @return const __FlashStringHelper *
 */
const std::string_view MFRC522Debug::PICC_GetTypeName(PICC_Type piccType  ///< One of the PICC_Type enums.
                                                         ) {
  switch(piccType) {
    case PICC_Type::PICC_TYPE_ISO_14443_4:
      return {"PICC compliant with ISO/IEC 14443-4"};
    case PICC_Type::PICC_TYPE_ISO_18092:
      return {"PICC compliant with ISO/IEC 18092 (NFC)"};
    case PICC_Type::PICC_TYPE_MIFARE_MINI:
      return {"MIFARE Mini, 320 bytes"};
    case PICC_Type::PICC_TYPE_MIFARE_1K:
      return {"MIFARE 1KB"};
    case PICC_Type::PICC_TYPE_MIFARE_4K:
      return {"MIFARE 4KB"};
    case PICC_Type::PICC_TYPE_MIFARE_UL:
      return {"MIFARE Ultralight or Ultralight C"};
    case PICC_Type::PICC_TYPE_MIFARE_PLUS:
      return {"MIFARE Plus"};
    case PICC_Type::PICC_TYPE_MIFARE_DESFIRE:
      return {"MIFARE DESFire"};
    case PICC_Type::PICC_TYPE_TNP3XXX:
      return {"MIFARE TNP3XXX"};
    case PICC_Type::PICC_TYPE_NOT_COMPLETE:
      return {"SAK indicates UID is not complete."};
    case PICC_Type::PICC_TYPE_UNKNOWN:
    default:
      return {"Unknown type"};
  }
} // End PICC_GetTypeName()

/**
 * Returns a __FlashStringHelper pointer to a status code name.
 * 
 * @return const __FlashStringHelper *
 */
const std::string_view MFRC522Debug::GetStatusCodeName(StatusCode code  ///< One of the StatusCode enums.
                                                          ) {
  switch(code) {
    case StatusCode::STATUS_OK:
      return {"Success."};
    case StatusCode::STATUS_ERROR:
      return {"Error in communication."};
    case StatusCode::STATUS_COLLISION:
      return {"collision detected."};
    case StatusCode::STATUS_TIMEOUT:
      return {"Timeout in communication."};
    case StatusCode::STATUS_NO_ROOM:
      return {"A buffer is not big enough."};
    case StatusCode::STATUS_INTERNAL_ERROR:
      return {"Internal error in the code. Should not happen."};
    case StatusCode::STATUS_INVALID:
      return {"Invalid argument."};
    case StatusCode::STATUS_CRC_WRONG:
      return {"The CRC_A does not match."};
    case StatusCode::STATUS_MIFARE_NACK:
      return {"A MIFARE PICC responded with NAK."};
    default:
      return {"Unknown error"};
  }
} // End GetStatusCodeName()

void MFRC522Debug::PrintUID(std::ostream &os, const MFRC522Constants::Uid &uid) {
    for (uint8_t i = 0; i < uid.size; i++) {
        if (uid.uidByte[i] < 0x10) os << " 0";
        else                       os << ' ';
        os << std::hex << (int)uid.uidByte[i];
    }
    os << std::dec;  // revert to decimal
}

// ------------------------------------------------------------
// PrintSelectedUID
// ------------------------------------------------------------
void MFRC522Debug::PrintSelectedUID(MFRC522 &device, std::ostream &os) {
    PrintUID(os, device.uid);
    os << std::endl;
}

// ------------------------------------------------------------
// PCD_DumpVersionToSerial
// ------------------------------------------------------------
void MFRC522Debug::PCD_DumpVersionToSerial(MFRC522 &device, std::ostream &os) {
    PCD_Version version = device.PCD_GetVersion();

    if (version != PCD_Version::Version_Unknown) {
        os << "Firmware Version: 0x"
           << std::hex << (int)version << std::dec;
    }

    switch(version) {
        case 0xb2:
            os << " = FM17522_1" << std::endl;
            break;
        case 0x88:
            os << " = FM17522" << std::endl;
            break;
        case 0x89:
            os << " = FM17522E" << std::endl;
            break;
        case 0x90:
            os << " = v0.0" << std::endl;
            break;
        case 0x91:
            os << " = v1.0" << std::endl;
            break;
        case 0x92:
            os << " = v2.0" << std::endl;
            break;
        case 0x12:
            os << " = counterfeit chip" << std::endl;
            break;
        default:
            os << " = (unknown)" << std::endl;
            break;
    }

    if (version == PCD_Version::Version_Unknown) {
        os << "WARNING: Communication failure, is the MFRC522 properly connected?"
           << std::endl;
    }
}

// ------------------------------------------------------------
// PICC_DumpToSerial
// ------------------------------------------------------------
void MFRC522Debug::PICC_DumpToSerial(MFRC522 &device, std::ostream &os, MFRC522Constants::Uid *uid) {
    MIFARE_Key key;
    // Dump UID, SAK and Type
    PICC_DumpDetailsToSerial(device, os, uid);

    // Dump contents
    PICC_Type piccType = device.PICC_GetType(uid->uidByte[/*sak*/1]); 
    // Adjust indexing if your code uses uid->sak at a known offset. 
    // This is placeholder logic since 'sak' might be a separate field in your real code.

    switch(piccType) {
        case PICC_Type::PICC_TYPE_MIFARE_MINI:
        case PICC_Type::PICC_TYPE_MIFARE_1K:
        case PICC_Type::PICC_TYPE_MIFARE_4K:
            for(uint8_t i = 0; i < 6; i++) {
                key.keyByte[i] = 0xFF;
            }
            PICC_DumpMifareClassicToSerial(device, os, uid, piccType, &key);
            break;

        case PICC_Type::PICC_TYPE_MIFARE_UL:
            PICC_DumpMifareUltralightToSerial(device, os);
            break;

        case PICC_Type::PICC_TYPE_ISO_14443_4:
        case PICC_Type::PICC_TYPE_MIFARE_DESFIRE:
        case PICC_Type::PICC_TYPE_ISO_18092:
        case PICC_Type::PICC_TYPE_MIFARE_PLUS:
        case PICC_Type::PICC_TYPE_TNP3XXX:
            os << "Dumping memory contents not implemented for that PICC type."
               << std::endl;
            break;

        case PICC_Type::PICC_TYPE_UNKNOWN:
        case PICC_Type::PICC_TYPE_NOT_COMPLETE:
        default:
            break; // No memory dump
    }

    os << std::endl;
    device.PICC_HaltA();
}

// ------------------------------------------------------------
// PICC_DumpDetailsToSerial
// ------------------------------------------------------------
void MFRC522Debug::PICC_DumpDetailsToSerial(MFRC522 &device, std::ostream &os, MFRC522Constants::Uid *uid) {
    // UID
    os << "Card UID:";
    for(uint8_t i = 0; i < uid->size; i++) {
        if(uid->uidByte[i] < 0x10) os << " 0";
        else                       os << " ";
        os << std::hex << (int)uid->uidByte[i];
    }
    os << std::dec << std::endl;

    // If you have a separate uid->sak field, just show it in hex:
    // os << "Card SAK: " << std::hex << (int)uid->sak << std::dec << std::endl;

    // PICC type
    PICC_Type piccType = device.PICC_GetType(uid->uidByte[/*sak index*/1]); 
    os << "PICC type: " << PICC_GetTypeName(piccType) << std::endl;
}

// ------------------------------------------------------------
// PICC_DumpMifareClassicToSerial
// ------------------------------------------------------------
void MFRC522Debug::PICC_DumpMifareClassicToSerial(MFRC522 &device, std::ostream &os,
                                                  MFRC522Constants::Uid *uid,
                                                  PICC_Type piccType,
                                                  MIFARE_Key *key) {
    uint8_t no_of_sectors = 0;

    switch(piccType) {
        case PICC_Type::PICC_TYPE_MIFARE_MINI:
            no_of_sectors = 5;
            break;
        case PICC_Type::PICC_TYPE_MIFARE_1K:
            no_of_sectors = 16;
            break;
        case PICC_Type::PICC_TYPE_MIFARE_4K:
            no_of_sectors = 40;
            break;
        default:
            // Should not happen
            break;
    }

    if(no_of_sectors) {
        os << "Sector Block   0  1  2  3   4  5  6  7   8  9 10 11  12 13 14 15  AccessBits"
           << std::endl;
        for(int8_t i = no_of_sectors - 1; i >= 0; i--) {
            PICC_DumpMifareClassicSectorToSerial(device, os, uid, key, i);
        }
    }

    device.PICC_HaltA();
    device.PCD_StopCrypto1();
}

// ------------------------------------------------------------
// PICC_DumpMifareClassicSectorToSerial
// ------------------------------------------------------------
void MFRC522Debug::PICC_DumpMifareClassicSectorToSerial(MFRC522 &device, std::ostream &os,
                                                        MFRC522Constants::Uid *uid,
                                                        MIFARE_Key *key,
                                                        uint8_t sector) {
    StatusCode status;
    uint8_t firstBlock;
    uint8_t no_of_blocks;
    bool isSectorTrailer;

    // Determine position and size of sector
    if(sector < 32) {
        no_of_blocks = 4;
        firstBlock   = sector * no_of_blocks;
    } else if(sector < 40) {
        no_of_blocks = 16;
        firstBlock   = 128 + (sector - 32) * no_of_blocks;
    } else {
        return;
    }

    uint8_t buffer[18];
    uint8_t byteCount;
    bool invertedError = false;

    isSectorTrailer = true;

    for(int8_t blockOffset = no_of_blocks - 1; blockOffset >= 0; blockOffset--) {
        uint8_t blockAddr = firstBlock + blockOffset;

        // Print sector & block labels
        if(isSectorTrailer) {
            os << std::setw(4) << (int)sector << "   ";
        } else {
            os << "       ";
        }

        os << std::setw(3) << (int)blockAddr << "  ";

        // Authenticate
        if(isSectorTrailer) {
            status = device.PCD_Authenticate(PICC_Command::PICC_CMD_MF_AUTH_KEY_A, firstBlock, key, uid);
            if(status != StatusCode::STATUS_OK) {
                os << "PCD_Authenticate() failed: "
                   << GetStatusCodeName(status) << std::endl;
                return;
            }
        }

        // Read block
        byteCount = sizeof(buffer);
        status = device.MIFARE_Read(blockAddr, buffer, &byteCount);
        if(status != StatusCode::STATUS_OK) {
            os << "MIFARE_Read() failed: "
               << GetStatusCodeName(status) << std::endl;
            continue;
        }

        // Hex dump
        for(uint8_t index = 0; index < 16; index++) {
            if(buffer[index] < 0x10) os << " 0";
            else                     os << " ";
            os << std::hex << (int)buffer[index];
            if((index % 4) == 3) os << " ";
        }
        os << std::dec;  // revert to decimal formatting for logic if needed

        // Parse sector trailer if necessary (access bits, etc.)
        if(isSectorTrailer) {
            // ... your existing logic for c1, c2, c3 ...
            // (omitted here for brevity, but you would just stream the results with `os << ...`)
            isSectorTrailer = false;
        }

        // Example: print a newline after each block
        os << std::endl;
    }
}

// ------------------------------------------------------------
// PICC_DumpMifareUltralightToSerial
// ------------------------------------------------------------
void MFRC522Debug::PICC_DumpMifareUltralightToSerial(MFRC522 &device, std::ostream &os) {
    StatusCode status;
    uint8_t    buffer[18];
    uint8_t    byteCount;

    os << "Page  0  1  2  3" << std::endl;

    for(uint8_t page = 0; page < 16; page += 4) {
        // Read 4 pages
        byteCount = sizeof(buffer);
        status = device.MIFARE_Read(page, buffer, &byteCount);
        if(status != StatusCode::STATUS_OK) {
            os << "MIFARE_Read() failed: "
               << GetStatusCodeName(status) << std::endl;
            break;
        }
        // Dump data
        for(uint8_t offset = 0; offset < 4; offset++) {
            uint8_t pageNum = page + offset;
            os << std::setw(3) << (int)pageNum << "  ";
            for(uint8_t index = 0; index < 4; index++) {
                uint8_t val = buffer[4*offset + index];
                if(val < 0x10) os << " 0";
                else           os << " ";
                os << std::hex << (int)val;
            }
            os << std::dec << std::endl;
        }
    }
}
