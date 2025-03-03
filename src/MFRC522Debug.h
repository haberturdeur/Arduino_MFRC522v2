/* SPDX-License-Identifier: LGPL-2.1 */
#pragma once

#include <MFRC522Constants.h>
#include <MFRC522v2.h>

#include <iostream>
#include <string_view>
#include <cstdint>

class MFRC522Debug {
private:
  using StatusCode = MFRC522Constants::StatusCode;
  using PICC_Type = MFRC522Constants::PICC_Type;
  using PICC_Command = MFRC522Constants::PICC_Command;
  using PCD_Version = MFRC522Constants::PCD_Version;
  using Uid = MFRC522Constants::Uid;
  using MIFARE_Key = MFRC522Constants::MIFARE_Key;

public:
  // Get human readable code and type
  static const std::string_view PICC_GetTypeName(PICC_Type type);
  static const std::string_view GetStatusCodeName(StatusCode code);
  
  // Support functions for debugging
  // Injected Arduino API with Print* could be replaced by void* if required.
  static void PrintUID(std::ostream &logPrint, const Uid &uid);
  static void PrintSelectedUID(MFRC522 &device, std::ostream &logPrint);
  static void PCD_DumpVersionToSerial(MFRC522 &device, std::ostream &logPrint);
  
  static void PICC_DumpToSerial(MFRC522 &device, std::ostream &logPrint, Uid *uid);
  static void PICC_DumpDetailsToSerial(MFRC522 &device, std::ostream &logPrint, Uid *uid);
  static void PICC_DumpMifareClassicToSerial(MFRC522 &device, std::ostream &logPrint, Uid *uid, PICC_Type piccType, MIFARE_Key *key);
  static void PICC_DumpMifareClassicSectorToSerial(MFRC522 &device, std::ostream &logPrint, Uid *uid, MIFARE_Key *key, std::uint8_t sector);
  static void PICC_DumpMifareUltralightToSerial(MFRC522 &device, std::ostream &logPrint);
};
