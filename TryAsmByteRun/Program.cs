using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Gee.External.Capstone;
using Gee.External.Capstone.X86;

namespace MMOvrAnalyzer
{
    class Program
    {
        // Класс для конфигурации файлов (заменили константы)
        class OverlayConfig
        {
            public string FileName { get; set; }
            public ushort TextBaseAddr { get; set; }
            public ushort PatchBase { get; set; }
        }

        // Глобальный список для отслеживания проанализированных объектов
        private static int currentObjectIndex = 0;
        private static List<AlternativePath> alternativePaths = new List<AlternativePath>();
        private static uint currentPatchAddress = 0;

        // Статическое поле для трекера регистров
        private static RegisterTracker registerTracker = new RegisterTracker();

        // Для отслеживания реального пути выполнения
        private static HashSet<uint> realExecutionAddresses = new HashSet<uint>();

        // Глобальный набор для отслеживания уже проанализированных путей (чтобы избежать циклов)
        private static HashSet<string> globallyAnalyzedPaths = new HashSet<string>();

        class AlternativePath
        {
            public int ObjectIndex { get; set; }
            public uint Address { get; set; }
            public string Condition { get; set; }
            public uint TargetAddress { get; set; }
            public bool Analyzed { get; set; }
        }

        static void Main(string[] args)
        {
            string filename;

            if (args.Length > 0)
            {
                filename = args[0];
            }
            else
            {
                filename = @"C:\GOG Games\Might and Magic 1\SORPIGAL.OVR";
            }

            // Получаем конфигурацию для файла
            OverlayConfig config = GetConfigForFile(filename);

            if (!File.Exists(filename))
            {
                Console.WriteLine($"File not found: {filename}");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            try
            {
                Console.WriteLine($"Analyzing overlay: {filename}");
                Console.WriteLine($"Configuration: TEXT_BASE_ADDR=0x{config.TextBaseAddr:X4}, PATCH_BASE=0x{config.PatchBase:X4}");
                Console.WriteLine($"File size: {new FileInfo(filename).Length} bytes");
                Console.WriteLine("=".PadRight(70, '='));
                AnalyzeOverlay(filename, config);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nERROR: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        // Метод для определения конфигурации по имени файла
        static OverlayConfig GetConfigForFile(string filename)
        {
            string fileNameOnly = Path.GetFileName(filename).ToUpper();

            switch (fileNameOnly)
            {
                case "SORPIGAL.OVR":
                    return new OverlayConfig
                    {
                        FileName = filename,
                        TextBaseAddr = 0xC5EC,
                        PatchBase = 0x0B7F
                    };

                // Добавьте другие файлы по мере необходимости
                // case "FILE2.OVR":
                //     return new OverlayConfig { ... };

                default:
                    // Заглушка для неизвестных файлов - можно запросить значения у пользователя
                    Console.WriteLine($"\nUnknown file: {fileNameOnly}");
                    Console.WriteLine("Please provide configuration values:");

                    Console.Write("TEXT_BASE_ADDR (hex, e.g., C5EC): ");
                    string textBaseStr = Console.ReadLine();
                    ushort textBase = Convert.ToUInt16(textBaseStr, 16);

                    Console.Write("PATCH_BASE (hex, e.g., 0B7F): ");
                    string patchBaseStr = Console.ReadLine();
                    ushort patchBase = Convert.ToUInt16(patchBaseStr, 16);

                    return new OverlayConfig
                    {
                        FileName = filename,
                        TextBaseAddr = textBase,
                        PatchBase = patchBase
                    };
            }
        }

        // Вспомогательный метод для чтения 16-битного значения из памяти
        static ushort ReadUInt16At(BinaryReader br, ushort address)
        {
            long originalPos = br.BaseStream.Position;
            try
            {
                br.BaseStream.Position = address;
                return br.ReadUInt16();
            }
            finally
            {
                br.BaseStream.Position = originalPos;
            }
        }

        // Метод для восстановления реального пути выполнения
        static List<X86Instruction> ReconstructExecutionPath(BinaryReader br, uint startAddress, OverlayConfig config)
        {
            var path = new List<X86Instruction>();
            var visitedAddresses = new HashSet<uint>();

            // Очищаем набор реальных адресов
            realExecutionAddresses.Clear();

            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                uint currentAddress = startAddress;
                const int MAX_INSTRUCTIONS = 200;
                int instructionCount = 0;

                while (currentAddress < br.BaseStream.Length && instructionCount < MAX_INSTRUCTIONS)
                {
                    if (visitedAddresses.Contains(currentAddress))
                    {
                        // Обнаружен цикл
                        break;
                    }

                    visitedAddresses.Add(currentAddress);
                    realExecutionAddresses.Add(currentAddress);

                    int bytesToRead = (int)Math.Min(32, br.BaseStream.Length - currentAddress);
                    byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);

                    var instructions = capstone.Disassemble(chunk, currentAddress);
                    if (instructions == null || instructions.Length == 0)
                        break;

                    bool processedInstruction = false;
                    foreach (var insn in instructions)
                    {
                        if (instructionCount >= MAX_INSTRUCTIONS)
                            break;

                        path.Add(insn);
                        realExecutionAddresses.Add((uint)insn.Address);
                        instructionCount++;
                        processedInstruction = true;

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // Обрабатываем переходы
                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, br.BaseStream.Length);
                            if (jumpTarget != 0)
                            {
                                if (jumpTarget < br.BaseStream.Length)
                                {
                                    currentAddress = jumpTarget;
                                }
                                else
                                {
                                    // JMP за пределами файла - останавливаемся
                                    return path;
                                }
                            }
                            else
                            {
                                currentAddress = nextAddress;
                            }
                            break;
                        }
                        else if (mnemonicUpper.StartsWith("J") && !mnemonicUpper.StartsWith("JMP"))
                        {
                            // Для условных переходов - идем по основному пути (не берем альтернативный)
                            // Это упрощение, но для начального анализа достаточно
                            currentAddress = nextAddress;
                            break;
                        }
                        else if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            return path; // Конец подпрограммы
                        }
                        else if (mnemonicUpper.StartsWith("CALL"))
                        {
                            uint callTarget = GetInstructionTargetAddress(insn, br.BaseStream.Length);
                            if (callTarget != 0 && callTarget < br.BaseStream.Length)
                            {
                                // Добавляем адрес вызова в реальные адреса
                                realExecutionAddresses.Add(callTarget);

                                // Анализируем подпрограмму, но ограничиваем глубину
                                if (path.Count < MAX_INSTRUCTIONS / 2)
                                {
                                    var subroutinePath = ReconstructExecutionPath(br, callTarget, config);
                                    path.AddRange(subroutinePath);
                                }
                            }
                            currentAddress = nextAddress;
                            break;
                        }
                        else
                        {
                            currentAddress = nextAddress;
                        }
                    }

                    if (!processedInstruction)
                        break;
                }
            }

            return path;
        }

        // Метод для проверки использования адреса позже в пути выполнения
        static void CheckIfAddressUsedLater(BinaryReader br, ushort address, List<X86Instruction> path, int startIndex, OverlayConfig config)
        {
            for (int i = startIndex; i < path.Count; i++)
            {
                var insn = path[i];
                byte[] instructionBytes = insn.Bytes;

                // Проверяем, используется ли этот адрес в записи в [3BD4]
                if (instructionBytes.Length >= 4 &&
                    instructionBytes[0] == 0x89 && instructionBytes[1] == 0x06 &&
                    instructionBytes[2] == 0xD4 && instructionBytes[3] == 0x3B)
                {
                    // MOV [3BD4], регистр - проверяем значение регистра
                    Console.WriteLine($"        ^ This address may be written to [3BD4] at 0x{insn.Address:X4}");
                    break;
                }
                else if (instructionBytes.Length >= 6 &&
                         instructionBytes[0] == 0xC7 && instructionBytes[1] == 0x06 &&
                         instructionBytes[2] == 0xD4 && instructionBytes[3] == 0x3B)
                {
                    // MOV [3BD4], непосредственное значение
                    ushort directAddr = BitConverter.ToUInt16(instructionBytes, 4);
                    if (directAddr == address)
                    {
                        Console.WriteLine($"        ^ This address is written to [3BD4] directly at 0x{insn.Address:X4}");
                    }
                }
            }
        }

        // Метод для проверки доступности перехода из текущего пути
        static bool IsTransitionReachableFromCurrentPath(BinaryReader br, uint currentPathAddress, uint jumpInstructionAddress)
        {
            // Простая проверка: если адрес перехода больше текущего адреса в пределах разумного диапазона,
            // считаем его доступным (это упрощение)
            if (jumpInstructionAddress > currentPathAddress && (jumpInstructionAddress - currentPathAddress) < 0x100)
            {
                return true;
            }

            // Более сложная проверка: анализируем код между currentPathAddress и jumpInstructionAddress
            try
            {
                using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
                {
                    capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                    uint currentAddress = currentPathAddress;
                    const int MAX_CHECK = 20;
                    int checks = 0;

                    while (currentAddress < jumpInstructionAddress && checks < MAX_CHECK)
                    {
                        int bytesToRead = (int)Math.Min(32, jumpInstructionAddress - currentAddress + 16);
                        byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);

                        var instructions = capstone.Disassemble(chunk, currentAddress);
                        if (instructions == null || instructions.Length == 0)
                            break;

                        foreach (var insn in instructions)
                        {
                            string mnemonicUpper = insn.Mnemonic.ToUpper();

                            // Если встретили безусловный переход или RET до нужной инструкции,
                            // значит переход недоступен
                            if (mnemonicUpper == "JMP" || mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                            {
                                return false;
                            }

                            // Если достигли адреса перехода - он доступен
                            if ((uint)insn.Address >= jumpInstructionAddress)
                            {
                                return true;
                            }

                            currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                            checks++;
                        }
                    }

                    return true; // Если не нашли препятствий, считаем доступным
                }
            }
            catch
            {
                return true; // При ошибке считаем доступным
            }
        }

        // Метод для проверки доступности вложенного перехода из альтернативного пути
        static bool IsTransitionReachableFromAlternativePath(BinaryReader br, uint patchAddress, uint mainJumpAddress,
            uint alternativeStartAddress, uint nestedJumpAddress)
        {
            try
            {
                using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
                {
                    capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                    uint currentAddress = alternativeStartAddress;
                    const int MAX_CHECK = 50;
                    int checks = 0;

                    while (currentAddress < nestedJumpAddress && checks < MAX_CHECK)
                    {
                        int bytesToRead = (int)Math.Min(32, nestedJumpAddress - currentAddress + 16);
                        byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);

                        var instructions = capstone.Disassemble(chunk, currentAddress);
                        if (instructions == null || instructions.Length == 0)
                            break;

                        foreach (var insn in instructions)
                        {
                            string mnemonicUpper = insn.Mnemonic.ToUpper();

                            // Если встретили безусловный переход или RET до нужной инструкции,
                            // значит переход недоступен
                            if (mnemonicUpper == "JMP" || mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                            {
                                // Если это JMP, проверяем куда он ведет
                                if (mnemonicUpper == "JMP")
                                {
                                    uint jumpTarget = GetInstructionTargetAddress(insn, br.BaseStream.Length);
                                    // Если JMP ведет куда-то другому, а не к нашему nestedJumpAddress
                                    if (jumpTarget != nestedJumpAddress)
                                    {
                                        return false;
                                    }
                                }
                                else
                                {
                                    return false; // RET всегда завершает путь
                                }
                            }

                            // Если достигли адреса перехода - он доступен
                            if ((uint)insn.Address >= nestedJumpAddress)
                            {
                                return true;
                            }

                            // Проверяем, не встретили ли мы другой условный переход, который может изменить поток
                            if (mnemonicUpper.StartsWith("J") && !mnemonicUpper.StartsWith("JMP"))
                            {
                                // Если это другой условный переход ДО нашего nestedJumpAddress,
                                // и он не ведет к nestedJumpAddress, то наш переход может быть недоступен
                                uint jumpTarget = GetInstructionTargetAddress(insn, br.BaseStream.Length);
                                if (jumpTarget != nestedJumpAddress && jumpTarget < nestedJumpAddress)
                                {
                                    // Этот другой переход может изменить поток выполнения
                                    return false;
                                }
                            }

                            currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                            checks++;
                        }
                    }

                    // Если не нашли препятствий, считаем доступным
                    return currentAddress >= nestedJumpAddress;
                }
            }
            catch
            {
                return true; // При ошибке считаем доступным
            }
        }

        // Метод для анализа косвенных путей загрузки текста в реальном пути выполнения
        static List<string> AnalyzeIndirectTextPatterns(BinaryReader br, uint patchAddress, OverlayConfig config)
        {
            var foundTexts = new List<string>();
            Console.WriteLine("  Analyzing indirect text loading patterns in execution path...");

            // Восстанавливаем реальный путь выполнения
            var executionPath = ReconstructExecutionPath(br, patchAddress, config);

            if (executionPath.Count == 0)
            {
                Console.WriteLine("    Could not reconstruct execution path");
                return foundTexts;
            }

            Console.WriteLine($"  Execution path reconstructed with {executionPath.Count} instructions");

            // Анализируем только реальный путь выполнения
            bool foundIndirectPattern = false;

            for (int i = 0; i < executionPath.Count; i++)
            {
                var insn = executionPath[i];
                byte[] instructionBytes = insn.Bytes;
                uint address = (uint)insn.Address;

                // Ищем паттерн MOV AL, imm8
                if (instructionBytes.Length >= 2 && instructionBytes[0] == 0xB0) // MOV AL, imm8
                {
                    byte alValue = instructionBytes[1];

                    // Проверяем следующую инструкцию в пути выполнения
                    if (i + 1 < executionPath.Count)
                    {
                        var nextInsn = executionPath[i + 1];
                        byte[] nextBytes = nextInsn.Bytes;

                        // Проверяем MOV BP, imm16
                        if (nextBytes.Length >= 3 && nextBytes[0] == 0xBD) // MOV BP, imm16
                        {
                            ushort bpValue = BitConverter.ToUInt16(nextBytes, 1);
                            ushort combinedAddr = (ushort)((bpValue << 8) | alValue);

                            // Проверяем, является ли это текстовым адресом
                            string text = ExtractText(br, combinedAddr, config);
                            if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                            {
                                Console.WriteLine($"    ^ Found REAL indirect text loading:");
                                Console.WriteLine($"        MOV AL, 0x{alValue:X2} at 0x{address:X4}");
                                Console.WriteLine($"        MOV BP, 0x{bpValue:X4} at 0x{nextInsn.Address:X4}");
                                Console.WriteLine($"        Combined address: 0x{combinedAddr:X4}");
                                Console.WriteLine($"        Text: {text}");
                                foundIndirectPattern = true;

                                // Добавляем найденный текст в список
                                string prefix = "  ";
                                string indirectTextEntry = $"{prefix}Text at 0x{combinedAddr:X4} (indirect via AL+BP): \"{text}\"";
                                foundTexts.Add(indirectTextEntry);

                                // Также проверяем, используется ли этот адрес позже
                                CheckIfAddressUsedLater(br, combinedAddr, executionPath, i + 2, config);
                            }
                        }
                    }
                }
            }

            if (!foundIndirectPattern)
            {
                Console.WriteLine("    No indirect patterns found in execution path");
            }

            return foundTexts;
        }

        static void AnalyzeCallsWithFullDisassembly(BinaryReader br, uint address, HashSet<uint> analyzedAddresses,
            List<string> specialInstructions, int depth, OverlayConfig config)
        {
            if (depth > 5)
                return;

            if (analyzedAddresses.Contains(address))
                return;

            analyzedAddresses.Add(address);

            // Очищаем трекер регистров при входе в новую подпрограмму
            if (depth == 0)
                registerTracker.Clear();

            long fileLength = br.BaseStream.Length;
            if (address >= fileLength)
                return;

            string prefix = new string(' ', depth * 2);

            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                uint currentAddress = address;
                const int MAX_INSTRUCTIONS = 50;
                int instructionsShown = 0;

                while (currentAddress < fileLength && instructionsShown < MAX_INSTRUCTIONS)
                {
                    int bytesToRead = (int)Math.Min(32, fileLength - currentAddress);
                    byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);

                    var instructions = capstone.Disassemble(chunk, currentAddress);

                    if (instructions == null || instructions.Length == 0)
                        break;

                    foreach (var insn in instructions)
                    {
                        if (instructionsShown >= MAX_INSTRUCTIONS)
                            break;

                        Console.WriteLine($"{prefix}  0x{insn.Address:X4}: {insn.Mnemonic,-8} {insn.Operand}");
                        instructionsShown++;

                        // Ищем специальные инструкции в текущей инструкции и добавляем их в список
                        FindSpecialInInstruction(insn, br, registerTracker, depth, specialInstructions, config);

                        // Также отслеживаем регистры для сложных случаев
                        TrackRegisterOperations(insn, br, depth, config);

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        if (mnemonicUpper.StartsWith("CALL"))
                        {
                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                Console.WriteLine($"{prefix}    ^ Entering subroutine at 0x{callTarget:X4}");
                                AnalyzeCallsWithFullDisassembly(br, callTarget, analyzedAddresses, specialInstructions, depth + 1, config);
                                Console.WriteLine($"{prefix}    ^ Returning from subroutine at 0x{callTarget:X4}");
                            }
                        }

                        if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            Console.WriteLine($"{prefix}    ^ RET - end of subroutine");
                            return;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
                                Console.WriteLine($"{prefix}    ^ JMP outside file - stopping subroutine analysis");
                                return;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
                                currentAddress = jumpTarget;
                                break;
                            }
                        }

                        currentAddress = nextAddress;
                    }
                }

                if (instructionsShown >= MAX_INSTRUCTIONS)
                {
                    Console.WriteLine($"{prefix}    [...] (truncated at {MAX_INSTRUCTIONS} instructions)");
                }
            }
        }

        // Новый метод для отслеживания операций с регистрами
        static void TrackRegisterOperations(X86Instruction insn, BinaryReader br, int depth, OverlayConfig config)
        {
            string prefix = new string(' ', depth * 2);
            byte[] instructionBytes = insn.Bytes;
            uint address = (uint)insn.Address;

            // Загрузка непосредственного значения в 16-битный регистр
            if (instructionBytes.Length >= 3 &&
                (instructionBytes[0] & 0xF8) == 0xB8)  // B8-BF: MOV r16, imm16
            {
                ushort immediateValue = BitConverter.ToUInt16(instructionBytes, 1);
                byte opcode = instructionBytes[0];
                byte regIndex = (byte)(opcode - 0xB8);

                string[] regNames = { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI" };
                if (regIndex < regNames.Length)
                {
                    string regName = regNames[regIndex];
                    registerTracker.SetRegisterValue(regName, immediateValue, address, $"MOV {regName}, 0x{immediateValue:X4}");
                }
            }

            // Загрузка непосредственного значения в 8-битный регистр (AL, CL, DL, BL, AH, CH, DH, BH)
            else if (instructionBytes.Length >= 2 &&
                     (instructionBytes[0] & 0xF8) == 0xB0)  // B0-B7: MOV r8, imm8
            {
                byte immediateValue = instructionBytes[1];
                byte opcode = instructionBytes[0];
                byte regIndex = (byte)(opcode - 0xB0);

                string[] regNames8 = { "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH" };
                if (regIndex < regNames8.Length)
                {
                    string regName = regNames8[regIndex];

                    // Определяем соответствующий 16-битный регистр
                    string fullReg = "";
                    switch (regName)
                    {
                        case "AL": case "AH": fullReg = "AX"; break;
                        case "CL": case "CH": fullReg = "CX"; break;
                        case "DL": case "DH": fullReg = "DX"; break;
                        case "BL": case "BH": fullReg = "BX"; break;
                    }

                    if (!string.IsNullOrEmpty(fullReg))
                    {
                        registerTracker.TrackPartialRegisterOperation(fullReg, regName, immediateValue, address, $"MOV {regName}, 0x{immediateValue:X2}");
                    }
                }
            }

            // Запись 16-битного значения в память [3BD4]
            if (instructionBytes.Length >= 6 &&
                instructionBytes[0] == 0xC7 && instructionBytes[1] == 0x06 &&
                instructionBytes[2] == 0xD4 && instructionBytes[3] == 0x3B)
            {
                ushort immediateValue = BitConverter.ToUInt16(instructionBytes, 4);
                string text = ExtractText(br, immediateValue, config);
                if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                {
                    Console.WriteLine($"{prefix}    ^ Detected direct text: \"{text}\"");
                }
            }

            // Запись 16-битного регистра в память [3BD4]
            else if (instructionBytes.Length >= 4 &&
                     instructionBytes[0] == 0x89 && instructionBytes[1] == 0x06 &&
                     instructionBytes[2] == 0xD4 && instructionBytes[3] == 0x3B)
            {
                byte modRM = instructionBytes[1];
                byte regField = (byte)((modRM >> 3) & 0x07);

                string[] regNames = { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI" };
                if (regField < regNames.Length)
                {
                    string regName = regNames[regField];
                    if (registerTracker.TryGetRegisterValue(regName, out ushort value))
                    {
                        string text = ExtractText(br, value, config);
                        if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                        {
                            Console.WriteLine($"{prefix}    ^ Detected text via {regName}: \"{text}\"");
                        }
                    }
                }
            }
        }

        // Вспомогательный метод для обработки текстовых адресов
        static void ProcessTextAddress(ushort textAddr, uint insnAddress, string source, string prefix,
            BinaryReader br, List<string> output, OverlayConfig config)
        {
            // Проверяем, находится ли адрес в разумных пределах для текста
            if (textAddr >= config.TextBaseAddr && textAddr < config.TextBaseAddr + 0x1000)
            {
                string text = ExtractText(br, textAddr, config);
                if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                {
                    output.Add($"{prefix}    Text at 0x{textAddr:X4} ({source}): \"{text}\"");
                }
                else if (text.StartsWith("Cannot locate"))
                {
                    output.Add($"{prefix}    Text address 0x{textAddr:X4} points outside file ({source})");
                }
            }
        }

        static void AnalyzeOverlay(string filename, OverlayConfig config)
        {
            using (var fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
            using (var br = new BinaryReader(fs))
            {
                if (fs.Length < 0x400)
                {
                    Console.WriteLine("File too small to be a valid overlay");
                    return;
                }

                // Чтение количества объектов (смещение 0x386)
                fs.Seek(0x386, SeekOrigin.Begin);
                byte numObjects = br.ReadByte();
                Console.WriteLine($"\nNumber of objects: {numObjects} (0x{numObjects:X2})");
                Console.WriteLine("-".PadRight(70, '-'));

                var coordinates = ReadCoordinates(br, numObjects);
                var directions = ReadDirections(br, numObjects);
                var patchKeys = ReadPatchKeys(br, numObjects);

                for (int i = 0; i < numObjects; i++)
                {
                    currentObjectIndex = i + 1;
                    alternativePaths.Clear();
                    realExecutionAddresses.Clear();
                    globallyAnalyzedPaths.Clear(); // Очищаем глобальный набор при переходе к новому объекту

                    ProcessObject(br, currentObjectIndex, coordinates[i], directions[i], patchKeys[i], config);

                    // Анализируем альтернативные пути для этого объекта
                    AnalyzeAlternativePaths(br, currentObjectIndex, config);

                    // Добавляем паузу между объектами, если это не последний объект
                    if (i < numObjects - 1)
                    {
                        Console.WriteLine("\n" + "=".PadRight(70, '='));
                        Console.WriteLine($"Press any key to continue to next object (#{i + 2})...");
                        Console.ReadKey();
                    }
                }
            }
        }

        static void AnalyzeAlternativePaths(BinaryReader br, int objIndex, OverlayConfig config)
        {
            if (alternativePaths.Count == 0)
                return;

            Console.WriteLine($"\n{"=".PadRight(70, '=')}");

            // Используем while вместо for, потому что список может расширяться во время выполнения
            int currentIndex = 0;
            while (currentIndex < alternativePaths.Count)
            {
                var path = alternativePaths[currentIndex];
                if (path.Analyzed)
                {
                    currentIndex++;
                    continue;
                }

                Console.WriteLine($"\n[Path {currentIndex + 1} of {alternativePaths.Count} (including newly discovered)]");
                Console.WriteLine($"Condition: {path.Condition} at 0x{path.Address:X4}");
                Console.WriteLine($"Would jump to: 0x{path.TargetAddress:X4}");
                Console.Write($"Analyze this alternative path? (Y/N): ");

                var key = Console.ReadKey();
                Console.WriteLine();

                if (key.KeyChar == 'Y' || key.KeyChar == 'y')
                {
                    Console.Clear();
                    Console.WriteLine($"=== Alternative analysis for Object #{objIndex} (path {currentIndex + 1}) ===");
                    Console.WriteLine($"Condition: {path.Condition} at 0x{path.Address:X4} -> 0x{path.TargetAddress:X4}");
                    Console.WriteLine($"This shows execution if the condition is TRUE (jump taken)");
                    Console.WriteLine("-".PadRight(70, '-'));

                    // Проверяем, не анализировали ли мы уже этот путь
                    string globalPathKey = $"{currentPatchAddress:X4}_{path.Address:X4}_{path.TargetAddress:X4}";
                    if (globallyAnalyzedPaths.Contains(globalPathKey))
                    {
                        Console.WriteLine($"  INFO: This alternative path has already been analyzed globally");
                        Console.WriteLine($"  Skipping to avoid infinite loops...");
                        path.Analyzed = true;
                        currentIndex++;
                        continue;
                    }
                    globallyAnalyzedPaths.Add(globalPathKey);

                    // Анализируем альтернативный путь
                    AnalyzeAlternativePath(br, currentPatchAddress, path.Address, path.TargetAddress,
                        objIndex, currentIndex + 1, new HashSet<string>(), 0, config);

                    path.Analyzed = true;
                }
                else
                {
                    Console.WriteLine($"Skipping alternative path {currentIndex + 1}");
                }

                currentIndex++;

                // Добавляем паузу только если есть еще пути для анализа
                if (currentIndex < alternativePaths.Count)
                {
                    Console.WriteLine("\n" + "=".PadRight(70, '='));
                    Console.WriteLine($"Press any key to continue to next alternative path...");
                    Console.ReadKey();
                }
            }
        }

        static void AnalyzeAlternativePath(BinaryReader br, uint patchAddress, uint jumpAddress, uint alternativeStartAddress,
            int objIndex, int pathIndex, HashSet<string> alreadyAnalyzedPaths, int recursionDepth = 0, OverlayConfig config = null)
        {
            const int MAX_RECURSION_DEPTH = 3;

            if (recursionDepth > MAX_RECURSION_DEPTH)
            {
                Console.WriteLine($"  ПРЕДУПРЕЖДЕНИЕ: Достигнута максимальная глубина рекурсии ({MAX_RECURSION_DEPTH}), остановка");
                return;
            }

            long fileSize = br.BaseStream.Length;

            if (patchAddress >= fileSize)
            {
                Console.WriteLine($"  ERROR: Patch address 0x{patchAddress:X4} is outside file bounds");
                return;
            }

            // Проверяем, не анализировали ли мы уже этот путь
            string pathKey = $"{jumpAddress:X4}_{alternativeStartAddress:X4}";
            if (alreadyAnalyzedPaths.Contains(pathKey))
            {
                Console.WriteLine($"  INFO: This alternative path has already been analyzed");
                return;
            }
            alreadyAnalyzedPaths.Add(pathKey);

            // Проверяем, не ведет ли альтернативный путь к уже проанализированному адресу
            if (IsAlreadyAnalyzedAlternative(br, alternativeStartAddress, pathKey))
            {
                Console.WriteLine($"  INFO: Alternative path leads to already analyzed code");
                return;
            }

            // Локальный список для вложенных альтернативных путей, которые действительно доступны
            var localAlternativePaths = new List<AlternativePath>();

            // Читаем достаточно байт для анализа
            int bytesToRead = Math.Min(256, (int)(fileSize - patchAddress));
            byte[] patchData = ReadBytesAt(br, patchAddress, bytesToRead);

            Console.WriteLine($"  Patch starts at: 0x{patchAddress:X4}");
            Console.WriteLine($"  Conditional jump at: 0x{jumpAddress:X4}");
            Console.WriteLine($"  Alternative path starts at: 0x{alternativeStartAddress:X4}");

            // Если это вложенный путь, объясняем условия
            if (IsNestedPath(jumpAddress, alternativeStartAddress))
            {
                Console.WriteLine($"  [NOTE: To reach jump at 0x{jumpAddress:X4}, previous conditions must be met]");
            }

            Console.WriteLine("  Raw bytes (hex) from patch:");
            ShowRawBytes(patchData, patchAddress);

            // Список для сбора специальных инструкций в порядке выполнения
            var specialInstructions = new List<string>();

            // 1. Линейное дизассемблирование альтернативного пути
            Console.WriteLine("\n  Alternative path disassembly (showing execution with jump taken):");

            // Всегда показываем выполнение с начала патча
            ShowLinearDisassemblyWithAlternativeBranch(br, patchAddress, jumpAddress, alternativeStartAddress,
                localAlternativePaths, objIndex, 0, true, config);

            // 2. Анализ CALL инструкций в альтернативном пути
            Console.WriteLine("\n  Alternative path CALL analysis (showing execution with jump taken):");
            var analyzedCalls = new HashSet<uint>();

            // Используем специальный метод для вложенных путей
            if (IsNestedPath(jumpAddress, alternativeStartAddress))
            {
                Console.WriteLine($"  [NESTED PATH DETECTED: Additional conditions needed to reach 0x{jumpAddress:X4}]");
                AnalyzeCallsWithNestedAlternativeBranch(br, patchAddress, jumpAddress, alternativeStartAddress,
                    analyzedCalls, specialInstructions, 0, new HashSet<string>(), config);
            }
            else
            {
                AnalyzeCallsWithAlternativeBranch(br, patchAddress, jumpAddress, alternativeStartAddress,
                    analyzedCalls, specialInstructions, 0, 0, config);
            }

            // 3. Выводим специальные инструкции из альтернативного пути В ПОРЯДКЕ ВЫПОЛНЕНИЯ
            Console.WriteLine("\n  Special instructions in alternative path (in execution order):");

            // Убираем дубликаты и сортируем по адресу
            var uniqueInstructions = specialInstructions
                .Distinct()
                .OrderBy(ins => ExtractAddressForSorting(ins))
                .ToList();

            if (uniqueInstructions.Count > 0)
            {
                foreach (var instruction in uniqueInstructions)
                {
                    Console.WriteLine(instruction);
                }
            }
            else
            {
                Console.WriteLine("    No special instructions found");
            }

            // 4. Анализируем ВЛОЖЕННЫЕ альтернативные пути, которые действительно доступны из этого альтернативного пути
            if (localAlternativePaths.Count > 0)
            {
                Console.WriteLine($"\n  Found {localAlternativePaths.Count} REACHABLE nested alternative execution path(s) in this alternative path");

                for (int i = 0; i < localAlternativePaths.Count; i++)
                {
                    var nestedPath = localAlternativePaths[i];
                    if (nestedPath.Analyzed) continue;

                    Console.WriteLine($"\n  [Nested Path {i + 1}/{localAlternativePaths.Count}]");
                    Console.WriteLine($"  Condition: {nestedPath.Condition} at 0x{nestedPath.Address:X4}");
                    Console.WriteLine($"  Would jump to: 0x{nestedPath.TargetAddress:X4}");

                    // Проверяем, действительно ли этот путь доступен из альтернативного пути
                    if (IsTransitionReachableFromAlternativePath(br, patchAddress, jumpAddress, alternativeStartAddress, nestedPath.Address))
                    {
                        // Проверяем глобально, не анализировали ли мы уже этот путь
                        string nestedGlobalKey = $"{currentPatchAddress:X4}_{nestedPath.Address:X4}_{nestedPath.TargetAddress:X4}";
                        if (globallyAnalyzedPaths.Contains(nestedGlobalKey))
                        {
                            Console.WriteLine($"  [INFO] This nested path has already been analyzed globally - skipping");
                            continue;
                        }

                        Console.Write($"  Analyze this REACHABLE nested alternative path? (Y/N): ");

                        var key = Console.ReadKey();
                        Console.WriteLine();

                        if (key.KeyChar == 'Y' || key.KeyChar == 'y')
                        {
                            globallyAnalyzedPaths.Add(nestedGlobalKey);

                            Console.WriteLine($"\n  {"=".PadRight(60, '-')}");
                            Console.WriteLine($"  Nested alternative analysis for Object #{objIndex}, Path #{pathIndex}");
                            Console.WriteLine($"  Nested path: {i + 1}/{localAlternativePaths.Count}");
                            Console.WriteLine($"  From: {nestedPath.Condition} at 0x{nestedPath.Address:X4} -> 0x{nestedPath.TargetAddress:X4}");
                            Console.WriteLine($"  {"=".PadRight(60, '-')}");

                            // Анализируем вложенный альтернативный путь рекурсивно
                            AnalyzeAlternativePath(br, patchAddress, nestedPath.Address, nestedPath.TargetAddress,
                                objIndex, pathIndex * 10 + i + 1, alreadyAnalyzedPaths, recursionDepth + 1, config);

                            nestedPath.Analyzed = true;
                        }
                        else
                        {
                            Console.WriteLine($"  Skipping nested alternative path {i + 1}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"  [INFO] Nested path {i + 1} is NOT REACHABLE from this alternative path - skipping");
                    }
                }
            }
        }

        // Новый вспомогательный метод для проверки уже проанализированных альтернативных путей
        static bool IsAlreadyAnalyzedAlternative(BinaryReader br, uint address, string currentPathKey)
        {
            return false; // Временно возвращаем false, можно расширить логику
        }

        // Метод для проверки, является ли путь вложенным
        static bool IsNestedPath(uint jumpAddress, uint alternativeStartAddress)
        {
            // Определяем вложенный путь по нескольким критериям:
            // 1. jumpAddress не равен 0
            // 2. alternativeStartAddress > jumpAddress (переход вперед)
            // 3. jumpAddress > 0x0090 (в вашем примере это 0x00A1)
            // 4. Для конкретного случая jne 0xb1 на 0x00A1
            return jumpAddress != 0 &&
                   alternativeStartAddress > jumpAddress &&
                   jumpAddress > 0x0090;
        }

        // Метод для извлечения адреса для сортировки
        static uint ExtractAddressForSorting(string instruction)
        {
            int addrIndex = instruction.IndexOf("at 0x");
            if (addrIndex > 0)
            {
                string addrStr = instruction.Substring(addrIndex + 5);
                if (addrStr.Length >= 4)
                {
                    string hexAddr = addrStr.Substring(0, 4);
                    if (uint.TryParse(hexAddr, System.Globalization.NumberStyles.HexNumber, null, out uint addr))
                    {
                        return addr;
                    }
                }
            }
            return 0xFFFFFFFF;
        }

        static void ShowLinearDisassemblyWithAlternativeBranch(BinaryReader br, uint patchAddress,
            uint jumpAddress, uint alternativeStartAddress, List<AlternativePath> localAlternativePaths,
            int objIndex, int depth = 0, bool isMainAlternativeAnalysis = false, OverlayConfig config = null)
        {
            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                long fileLength = br.BaseStream.Length;
                uint currentAddress = patchAddress; // Начинаем с начала патча
                int instructionsShown = 0;
                const int MAX_INSTRUCTIONS = 100;

                // Улучшенная система отслеживания адресов для предотвращения циклов
                var processedAddresses = new Dictionary<uint, int>();
                bool jumpTaken = false;
                bool shouldStop = false;

                while (currentAddress < fileLength && instructionsShown < MAX_INSTRUCTIONS && !shouldStop)
                {
                    // Проверяем, не посещали ли мы этот адрес слишком много раз
                    if (processedAddresses.ContainsKey(currentAddress))
                    {
                        processedAddresses[currentAddress]++;
                        if (processedAddresses[currentAddress] > 3) // Максимум 3 посещения
                        {
                            Console.WriteLine($"        ^ Цикл обнаружен на адресе 0x{currentAddress:X4} (посещён {processedAddresses[currentAddress]} раз), остановка");
                            break;
                        }
                    }
                    else
                    {
                        processedAddresses[currentAddress] = 1;
                    }

                    int bytesToRead = (int)Math.Min(32, fileLength - currentAddress);
                    byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);

                    var instructions = capstone.Disassemble(chunk, currentAddress);

                    if (instructions == null || instructions.Length == 0)
                        break;

                    foreach (var insn in instructions)
                    {
                        if (instructionsShown >= MAX_INSTRUCTIONS || shouldStop)
                            break;

                        // Отмечаем важные моменты
                        string marker = "";
                        if (insn.Address == jumpAddress && !jumpTaken)
                        {
                            marker = " <-- УСЛОВНЫЙ ПЕРЕХОД (ВЫПОЛНЯЕТСЯ в этом сценарии)";
                        }
                        else if (insn.Address == alternativeStartAddress && jumpTaken)
                        {
                            marker = " <-- АЛЬТЕРНАТИВНЫЙ ПУТЬ ПРОДОЛЖАЕТСЯ ЗДЕСЬ";
                        }

                        Console.WriteLine($"    0x{insn.Address:X4}: {insn.Mnemonic,-8} {insn.Operand}{marker}");
                        instructionsShown++;

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // Если это тот самый условный переход - идем по альтернативной ветке
                        if (insn.Address == jumpAddress && !jumpTaken)
                        {
                            jumpTaken = true;

                            // Проверяем, не ведет ли альтернативный путь обратно в уже обработанную область
                            if (processedAddresses.ContainsKey(alternativeStartAddress))
                            {
                                Console.WriteLine($"        ^ ВНИМАНИЕ: Альтернативный путь ведет к уже обработанному адресу 0x{alternativeStartAddress:X4}");
                                Console.WriteLine($"        ^ Проверка на циклическую ссылку...");

                                // Проверяем, не будет ли это прямой циклической ссылкой
                                if (alternativeStartAddress <= currentAddress)
                                {
                                    Console.WriteLine($"        ^ ОБНАРУЖЕНА ЦИКЛИЧЕСКАЯ ССЫЛКА! Альтернативный путь ведет назад.");
                                    shouldStop = true;
                                    break;
                                }
                            }

                            currentAddress = alternativeStartAddress;
                            Console.WriteLine($"        ^ Переход ВЫПОЛНЕН к альтернативному пути по адресу 0x{alternativeStartAddress:X4}");
                            break;
                        }

                        // В альтернативном пути находим ВСЕ условные переходы и добавляем их как альтернативные пути
                        if (mnemonicUpper.StartsWith("J") &&
                            !mnemonicUpper.StartsWith("JMP") && !mnemonicUpper.StartsWith("JECXZ") &&
                            insn.Address != jumpAddress)
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);

                            if (jumpTarget != 0 && jumpTarget < fileLength)
                            {
                                // Проверяем, не ведет ли этот переход обратно в уже обработанную область
                                bool leadsToAlreadyProcessed = processedAddresses.ContainsKey(jumpTarget) ||
                                                              (jumpTarget < currentAddress && jumpTarget > patchAddress);

                                var altPath = new AlternativePath
                                {
                                    ObjectIndex = objIndex,
                                    Address = (uint)insn.Address,
                                    Condition = $"{insn.Mnemonic} {insn.Operand} (внутри альтернативного пути)",
                                    TargetAddress = jumpTarget,
                                    Analyzed = false
                                };

                                if (isMainAlternativeAnalysis)
                                {
                                    bool alreadyExists = alternativePaths.Any(p =>
                                        p.Address == altPath.Address && p.TargetAddress == altPath.TargetAddress);

                                    if (!alreadyExists)
                                    {
                                        alternativePaths.Add(altPath);
                                        if (leadsToAlreadyProcessed)
                                        {
                                            Console.WriteLine($"        ^ Найден вложенный альтернативный путь с ВОЗМОЖНОЙ циклической ссылкой: {insn.Mnemonic} {insn.Operand} -> 0x{jumpTarget:X4}");
                                        }
                                        else
                                        {
                                            Console.WriteLine($"        ^ Найден вложенный альтернативный путь внутри альтернативного: {insn.Mnemonic} {insn.Operand} -> 0x{jumpTarget:X4}");
                                        }
                                    }
                                }

                                localAlternativePaths.Add(altPath);
                            }
                        }

                        if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            Console.WriteLine("        ^ Обнаружен RET, остановка линейного дизассемблирования");
                            shouldStop = true;
                            break;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);

                            // Проверяем JMP на циклические ссылки
                            if (processedAddresses.ContainsKey(jumpTarget))
                            {
                                Console.WriteLine($"        ^ JMP ведет к уже обработанному адресу 0x{jumpTarget:X4}, возможный цикл");
                                if (jumpTarget >= patchAddress && jumpTarget < currentAddress)
                                {
                                    Console.WriteLine($"        ^ ОБНАРУЖЕН ЦИКЛ! JMP возвращается назад.");
                                    shouldStop = true;
                                    break;
                                }
                            }

                            if (jumpTarget >= fileLength)
                            {
                                Console.WriteLine($"        ^ JMP за пределами файла (0x{jumpTarget:X4}), остановка");
                                shouldStop = true;
                                break;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
                                Console.WriteLine($"        ^ JMP к 0x{jumpTarget:X4}");
                                currentAddress = jumpTarget;
                                break;
                            }
                        }
                        else
                        {
                            currentAddress = nextAddress;
                        }
                    }
                }

                if (instructionsShown >= MAX_INSTRUCTIONS && !shouldStop)
                {
                    Console.WriteLine($"    [...] (прервано после {MAX_INSTRUCTIONS} инструкций)");
                }
            }
        }

        static void AnalyzeCallsWithAlternativeBranch(BinaryReader br, uint patchAddress,
            uint jumpAddress, uint alternativeStartAddress, HashSet<uint> analyzedAddresses,
            List<string> specialInstructions, int depth, int callDepth = 0, OverlayConfig config = null)
        {
            const int MAX_CALL_DEPTH = 5;

            if (depth > MAX_CALL_DEPTH)
            {
                Console.WriteLine($"{new string(' ', depth * 2)}  ПРЕДУПРЕЖДЕНИЕ: Достигнута максимальная глубина вызовов ({MAX_CALL_DEPTH}), остановка");
                return;
            }

            if (analyzedAddresses.Contains(patchAddress))
                return;

            analyzedAddresses.Add(patchAddress);

            long fileLength = br.BaseStream.Length;
            if (patchAddress >= fileLength)
                return;

            string prefix = new string(' ', depth * 2);

            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                uint currentAddress = patchAddress;
                const int MAX_INSTRUCTIONS = 50;
                int instructionsShown = 0;
                bool jumpTaken = false;
                bool shouldStop = false;

                while (currentAddress < fileLength && instructionsShown < MAX_INSTRUCTIONS && !shouldStop)
                {
                    int bytesToRead = (int)Math.Min(32, fileLength - currentAddress);
                    byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);

                    var instructions = capstone.Disassemble(chunk, currentAddress);

                    if (instructions == null || instructions.Length == 0)
                        break;

                    foreach (var insn in instructions)
                    {
                        if (instructionsShown >= MAX_INSTRUCTIONS || shouldStop)
                            break;

                        // Отмечаем важные моменты
                        string marker = "";
                        if (insn.Address == jumpAddress && !jumpTaken)
                        {
                            marker = " <-- CONDITIONAL JUMP (TAKEN in this scenario)";
                        }
                        else if (insn.Address == alternativeStartAddress && jumpTaken)
                        {
                            marker = " <-- ALTERNATIVE PATH CONTINUES HERE";
                        }

                        Console.WriteLine($"{prefix}  0x{insn.Address:X4}: {insn.Mnemonic,-8} {insn.Operand}{marker}");
                        instructionsShown++;

                        // Ищем специальные инструкции в текущей инструкции и добавляем их в список
                        FindSpecialInInstruction(insn, br, registerTracker, depth, specialInstructions, config);

                        // Также отслеживаем регистры
                        TrackRegisterOperations(insn, br, depth, config);

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // Если это тот самый условный переход - идем по альтернативной ветке
                        if (insn.Address == jumpAddress && !jumpTaken)
                        {
                            jumpTaken = true;
                            currentAddress = alternativeStartAddress; // Переходим по альтернативной ветке
                            Console.WriteLine($"{prefix}    ^ Jump TAKEN to alternative path at 0x{alternativeStartAddress:X4}");
                            break;
                        }

                        if (mnemonicUpper.StartsWith("CALL"))
                        {
                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                Console.WriteLine($"{prefix}    ^ Entering subroutine at 0x{callTarget:X4}");

                                // ВАЖНОЕ ИСПРАВЛЕНИЕ: Передаем ТОТ ЖЕ список specialInstructions
                                AnalyzeCallsWithAlternativeBranch(br, callTarget, 0, 0,
                                    analyzedAddresses, specialInstructions, depth + 1, callDepth + 1, config);

                                Console.WriteLine($"{prefix}    ^ Returning from subroutine at 0x{callTarget:X4}");
                            }
                        }

                        if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            Console.WriteLine($"{prefix}    ^ RET - end of subroutine");
                            shouldStop = true;
                            break;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
                                Console.WriteLine($"{prefix}    ^ JMP outside file - stopping subroutine analysis");
                                shouldStop = true;
                                break;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
                                currentAddress = jumpTarget;
                                break;
                            }
                        }

                        currentAddress = nextAddress;
                    }
                }

                if (instructionsShown >= MAX_INSTRUCTIONS && !shouldStop)
                {
                    Console.WriteLine($"{prefix}    [...] (truncated at {MAX_INSTRUCTIONS} instructions)");
                }
            }
        }

        static void AnalyzeCallsWithNestedAlternativeBranch(BinaryReader br, uint patchAddress,
            uint jumpAddress, uint alternativeStartAddress, HashSet<uint> analyzedAddresses,
            List<string> specialInstructions, int depth, HashSet<string> alreadyAnalyzedConditions = null, OverlayConfig config = null)
        {
            if (depth > 5)
            {
                Console.WriteLine($"{new string(' ', depth * 2)}  ПРЕДУПРЕЖДЕНИЕ: Достигнута максимальная глубина анализа ({depth}), остановка");
                return;
            }

            // Инициализируем набор уже проанализированных условий, если его нет
            if (alreadyAnalyzedConditions == null)
            {
                alreadyAnalyzedConditions = new HashSet<string>();
            }

            string prefix = new string(' ', depth * 2);
            long fileLength = br.BaseStream.Length;

            // Создаем ключ для этого конкретного пути анализа
            string pathKey = $"{patchAddress:X4}_{jumpAddress:X4}_{alternativeStartAddress:X4}_{depth}";
            if (alreadyAnalyzedConditions.Contains(pathKey))
            {
                Console.WriteLine($"{prefix}  ИНФОРМАЦИЯ: Этот вложенный путь уже был проанализирован (ключ: {pathKey})");
                return;
            }
            alreadyAnalyzedConditions.Add(pathKey);

            Console.WriteLine($"{prefix}  [NESTED PATH ANALYSIS: 0x{jumpAddress:X4} -> 0x{alternativeStartAddress:X4}]");
            Console.WriteLine($"{prefix}  Conditions to reach this path:");

            // 1. Сначала анализируем, как достичь jumpAddress
            uint currentAddress = patchAddress;
            bool reachedJumpAddress = false;
            int maxSteps = 100; // Максимальное количество шагов для поиска jumpAddress
            int stepsTaken = 0;

            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                // Анализируем путь до jumpAddress с ограничением по количеству шагов
                while (currentAddress < jumpAddress && currentAddress < fileLength && stepsTaken < maxSteps)
                {
                    stepsTaken++;

                    // Создаем ключ для текущей позиции
                    string positionKey = $"{currentAddress:X4}_{jumpAddress:X4}";
                    if (alreadyAnalyzedConditions.Contains(positionKey))
                    {
                        Console.WriteLine($"{prefix}  ПРЕДУПРЕЖДЕНИЕ: Обнаружена циклическая ссылка при поиске jumpAddress");
                        break;
                    }
                    alreadyAnalyzedConditions.Add(positionKey);

                    int bytesToRead = (int)Math.Min(32, fileLength - currentAddress);
                    byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);
                    var instructions = capstone.Disassemble(chunk, currentAddress);

                    if (instructions == null || instructions.Length == 0)
                        break;

                    bool processedInstruction = false;
                    foreach (var insn in instructions)
                    {
                        if ((uint)insn.Address >= jumpAddress)
                        {
                            reachedJumpAddress = true;
                            break;
                        }

                        string mnemonic = insn.Mnemonic.ToUpper();

                        // Если это CALL - анализируем подпрограмму
                        if (mnemonic.StartsWith("CALL"))
                        {
                            Console.WriteLine($"{prefix}    0x{insn.Address:X4}: {insn.Mnemonic,-8} {insn.Operand}");

                            // Ищем специальные инструкции в инструкции CALL
                            FindSpecialInInstruction(insn, br, registerTracker, depth, specialInstructions, config);
                            TrackRegisterOperations(insn, br, depth, config);

                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                Console.WriteLine($"{prefix}      ^ Entering subroutine at 0x{callTarget:X4}");

                                // ВАЖНОЕ ИСПРАВЛЕНИЕ: Анализируем подпрограмму!
                                AnalyzeCallsWithAlternativeBranch(br, callTarget, 0, 0,
                                    analyzedAddresses, specialInstructions, depth + 1, 0, config);

                                Console.WriteLine($"{prefix}      ^ Returning from subroutine at 0x{callTarget:X4}");
                            }

                            currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                            processedInstruction = true;
                            break;
                        }
                        // Если это условный переход, отмечаем его как необходимое условие
                        else if (mnemonic.StartsWith("J") && !mnemonic.StartsWith("JMP") && !mnemonic.StartsWith("JECXZ"))
                        {
                            // Создаем строку условия для проверки
                            string conditionStr = $"{insn.Mnemonic} {insn.Operand} at 0x{insn.Address:X4}";

                            // Проверяем на циклическое условие
                            if (IsCyclicCondition(conditionStr, alreadyAnalyzedConditions, 2))
                            {
                                Console.WriteLine($"{prefix}    [ЦИКЛ] Условие {conditionStr} встречается слишком много раз, ПРОПУСК");

                                // Пропускаем этот переход и продолжаем линейно
                                currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                                processedInstruction = true;
                                break;
                            }

                            // Проверяем, не анализировали ли мы уже это условие
                            string conditionKey = $"{insn.Address:X4}_{insn.Mnemonic}_{insn.Operand}";
                            if (alreadyAnalyzedConditions.Contains(conditionKey))
                            {
                                Console.WriteLine($"{prefix}    [ПРОПУСК] Условие {insn.Mnemonic} {insn.Operand} уже было проанализировано");

                                // Пропускаем этот переход и продолжаем линейно
                                currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                                processedInstruction = true;
                                break;
                            }

                            Console.WriteLine($"{prefix}    - {conditionStr} must be TAKEN");
                            alreadyAnalyzedConditions.Add(conditionKey);
                            alreadyAnalyzedConditions.Add($"COND_{conditionStr}"); // Добавляем для проверки циклов

                            // Ищем специальные инструкции в этом переходе
                            FindSpecialInInstruction(insn, br, registerTracker, depth, specialInstructions, config);
                            TrackRegisterOperations(insn, br, depth, config);

                            // Переходим по этому переходу (предполагаем, что он выполняется)
                            uint target = GetInstructionTargetAddress(insn, fileLength);

                            // Проверяем, не ведет ли переход к уже обработанному адресу
                            if (alreadyAnalyzedConditions.Contains($"{target:X4}_visited"))
                            {
                                Console.WriteLine($"{prefix}    [ПРЕДУПРЕЖДЕНИЕ] Переход ведет к уже обработанному адресу 0x{target:X4}");
                                Console.WriteLine($"{prefix}    [РЕШЕНИЕ] Продолжаем линейное выполнение вместо перехода");

                                // Вместо перехода продолжаем линейно
                                currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                            }
                            else
                            {
                                // Отмечаем целевой адрес как посещенный
                                alreadyAnalyzedConditions.Add($"{target:X4}_visited");
                                currentAddress = target;
                            }

                            processedInstruction = true;
                            break;
                        }
                        else
                        {
                            // Обычные инструкции - показываем и ищем специальные инструкции
                            Console.WriteLine($"{prefix}    0x{insn.Address:X4}: {insn.Mnemonic,-8} {insn.Operand}");

                            // Ищем специальные инструкции и добавляем их в список
                            FindSpecialInInstruction(insn, br, registerTracker, depth, specialInstructions, config);
                            TrackRegisterOperations(insn, br, depth, config);

                            currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                            processedInstruction = true;
                            break;
                        }
                    }

                    if (!processedInstruction)
                        break;

                    if (reachedJumpAddress)
                        break;
                }

                // Проверяем, почему остановились
                if (stepsTaken >= maxSteps)
                {
                    Console.WriteLine($"{prefix}  [ПРЕДУПРЕЖДЕНИЕ] Достигнуто максимальное количество шагов ({maxSteps}) при поиске jumpAddress");
                }

                // 2. Теперь анализируем код начиная с jumpAddress (если достигли его)
                if (reachedJumpAddress)
                {
                    Console.WriteLine($"{prefix}  [REACHED JUMP AT 0x{jumpAddress:X4}, CONTINUING ANALYSIS]");

                    // Анализируем выполнение от jumpAddress до конца
                    AnalyzeSpecificJumpExecutionWithFullCollection(br, jumpAddress, alternativeStartAddress,
                        analyzedAddresses, specialInstructions, depth, prefix, config);
                }
                else
                {
                    Console.WriteLine($"{prefix}  [ERROR: Could not reach jump address 0x{jumpAddress:X4}]");
                    Console.WriteLine($"{prefix}  [TRYING DIRECT ANALYSIS FROM JUMP ADDRESS...]");

                    // Попробуем анализировать напрямую от jumpAddress
                    AnalyzeSpecificJumpExecutionWithFullCollection(br, jumpAddress, alternativeStartAddress,
                        analyzedAddresses, specialInstructions, depth, prefix, config);
                }
            }
        }

        // Метод для проверки циклических условий
        static bool IsCyclicCondition(string condition, HashSet<string> alreadyAnalyzedConditions, int maxRepetitions = 2)
        {
            try
            {
                // Извлекаем ключевые части условия
                // Формат: "jb 0x17b at 0x0188 must be TAKEN"
                string[] parts = condition.Split(' ');
                if (parts.Length >= 4)
                {
                    // Берем мнемонику и целевой адрес (например: "jb 0x17b")
                    string conditionKey = $"COND_{parts[0]}_{parts[1]}";

                    // Считаем, сколько раз встречалось это условие
                    int count = 0;
                    foreach (var item in alreadyAnalyzedConditions)
                    {
                        if (item.StartsWith(conditionKey))
                        {
                            count++;
                        }
                    }

                    // Если условие встречается слишком много раз - это цикл
                    if (count >= maxRepetitions)
                    {
                        Console.WriteLine($"  [ЦИКЛ ДЕТЕКТИРОВАН] Условие {parts[0]} {parts[1]} встречается {count} раз (максимум {maxRepetitions})");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ОШИБКА] При проверке условия на цикличность: {ex.Message}");
            }

            return false;
        }

        // Новый метод для анализа конкретного перехода с полным сбором специальных инструкций
        static void AnalyzeSpecificJumpExecutionWithFullCollection(BinaryReader br, uint jumpAddress, uint alternativeStartAddress,
            HashSet<uint> analyzedAddresses, List<string> specialInstructions, int depth, string prefix, OverlayConfig config)
        {
            if (analyzedAddresses.Contains(jumpAddress))
                return;

            analyzedAddresses.Add(jumpAddress);

            long fileLength = br.BaseStream.Length;

            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                uint currentAddress = jumpAddress;
                const int MAX_INSTRUCTIONS = 50;
                int instructionsShown = 0;
                bool jumpExecuted = false;

                while (currentAddress < fileLength && instructionsShown < MAX_INSTRUCTIONS)
                {
                    int bytesToRead = (int)Math.Min(32, fileLength - currentAddress);
                    byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);
                    var instructions = capstone.Disassemble(chunk, currentAddress);

                    if (instructions == null || instructions.Length == 0)
                        break;

                    foreach (var insn in instructions)
                    {
                        if (instructionsShown >= MAX_INSTRUCTIONS)
                            break;

                        string marker = "";
                        if (insn.Address == jumpAddress && !jumpExecuted)
                        {
                            marker = " <-- [THIS IS THE NESTED JUMP WE'RE ANALYZING]";
                        }
                        else if (insn.Address == alternativeStartAddress && jumpExecuted)
                        {
                            marker = " <-- [NESTED ALTERNATIVE PATH STARTS HERE]";
                        }

                        Console.WriteLine($"{prefix}    0x{insn.Address:X4}: {insn.Mnemonic,-8} {insn.Operand}{marker}");
                        instructionsShown++;

                        // Ищем специальные инструкции и добавляем их в список
                        FindSpecialInInstruction(insn, br, registerTracker, depth, specialInstructions, config);
                        TrackRegisterOperations(insn, br, depth, config);

                        string mnemonic = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // Если это наш целевой переход - выполняем его
                        if (insn.Address == jumpAddress && !jumpExecuted)
                        {
                            jumpExecuted = true;
                            Console.WriteLine($"{prefix}      ^ [EXECUTING NESTED JUMP] Continuing at 0x{alternativeStartAddress:X4}");
                            currentAddress = alternativeStartAddress;
                            break;
                        }

                        // Проверяем конец выполнения
                        if (mnemonic == "RET" || mnemonic == "RETF")
                        {
                            Console.WriteLine($"{prefix}      ^ [END OF PATH]");
                            return;
                        }

                        if (mnemonic == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
                                Console.WriteLine($"{prefix}      ^ [EXTERNAL JMP] Stopping");
                                return;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
                                Console.WriteLine($"{prefix}      ^ [JMP] Continuing at 0x{jumpTarget:X4}");
                                currentAddress = jumpTarget;
                                break;
                            }
                        }

                        if (mnemonic.StartsWith("CALL"))
                        {
                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                Console.WriteLine($"{prefix}      ^ Entering subroutine at 0x{callTarget:X4}");

                                // Анализируем подпрограмму
                                AnalyzeCallsWithAlternativeBranch(br, callTarget, 0, 0,
                                    analyzedAddresses, specialInstructions, depth + 1, 0, config);

                                Console.WriteLine($"{prefix}      ^ Returning from subroutine at 0x{callTarget:X4}");
                            }
                        }

                        currentAddress = nextAddress;
                    }
                }

                if (instructionsShown >= MAX_INSTRUCTIONS)
                {
                    Console.WriteLine($"{prefix}      [...] (truncated at {MAX_INSTRUCTIONS} instructions)");
                }
            }
        }

        static void ShowLinearDisassembly(BinaryReader br, uint startAddress, bool isAlternativePath, int depth,
            List<AlternativePath> localAlternativePaths = null, int objIndex = 0, OverlayConfig config = null)
        {
            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                long fileLength = br.BaseStream.Length;
                uint currentAddress = startAddress;
                int instructionsShown = 0;
                const int MAX_INSTRUCTIONS = 50;

                var processedAddresses = new Dictionary<uint, int>();

                while (currentAddress < fileLength && instructionsShown < MAX_INSTRUCTIONS)
                {
                    // Проверяем, не посещали ли мы этот адрес слишком много раз
                    if (processedAddresses.ContainsKey(currentAddress))
                    {
                        processedAddresses[currentAddress]++;
                        if (processedAddresses[currentAddress] > 2) // Максимум 2 посещения
                        {
                            Console.WriteLine($"        ^ Цикл обнаружен на адресе 0x{currentAddress:X4}, остановка");
                            break;
                        }
                    }
                    else
                    {
                        processedAddresses[currentAddress] = 1;
                    }

                    int bytesToRead = (int)Math.Min(32, fileLength - currentAddress);
                    byte[] chunk = ReadBytesAt(br, currentAddress, bytesToRead);

                    var instructions = capstone.Disassemble(chunk, currentAddress);

                    if (instructions == null || instructions.Length == 0)
                        break;

                    foreach (var insn in instructions)
                    {
                        if (instructionsShown >= MAX_INSTRUCTIONS)
                            break;

                        Console.WriteLine($"    0x{insn.Address:X4}: {insn.Mnemonic,-8} {insn.Operand}");
                        instructionsShown++;

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // В основном пути собираем ВСЕ альтернативные пути
                        if (!isAlternativePath && mnemonicUpper.StartsWith("J") &&
                            !mnemonicUpper.StartsWith("JMP") && !mnemonicUpper.StartsWith("JECXZ"))
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget != 0 && jumpTarget < fileLength)
                            {
                                var altPath = new AlternativePath
                                {
                                    ObjectIndex = currentObjectIndex,
                                    Address = (uint)insn.Address,
                                    Condition = $"{insn.Mnemonic} {insn.Operand}",
                                    TargetAddress = jumpTarget,
                                    Analyzed = false
                                };

                                // Проверяем, нет ли уже такого пути в списке
                                bool alreadyExists = alternativePaths.Any(p =>
                                    p.Address == altPath.Address && p.TargetAddress == altPath.TargetAddress);

                                if (!alreadyExists)
                                {
                                    alternativePaths.Add(altPath);
                                }
                            }
                        }

                        if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            Console.WriteLine("        ^ RET detected, stopping linear disassembly");
                            return;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
                                Console.WriteLine($"        ^ JMP outside file boundaries (0x{jumpTarget:X4}), stopping");
                                return;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
                                Console.WriteLine($"        ^ JMP to 0x{jumpTarget:X4}");
                                currentAddress = jumpTarget;
                                break;
                            }
                        }
                        else
                        {
                            currentAddress = nextAddress;
                        }
                    }
                }

                if (instructionsShown >= MAX_INSTRUCTIONS)
                {
                    Console.WriteLine($"    [...] (truncated at {MAX_INSTRUCTIONS} instructions)");
                }
            }
        }

        static Tuple<byte, byte>[] ReadCoordinates(BinaryReader br, int count)
        {
            var coords = new Tuple<byte, byte>[count];
            for (int i = 0; i < count; i++)
            {
                byte coordByte = br.ReadByte();
                byte y = (byte)(coordByte >> 4);
                byte x = (byte)(coordByte & 0x0F);
                coords[i] = Tuple.Create(x, y);
            }
            return coords;
        }

        static byte[] ReadDirections(BinaryReader br, int count)
        {
            var directions = new byte[count];
            for (int i = 0; i < count; i++)
            {
                directions[i] = br.ReadByte();
            }
            return directions;
        }

        static ushort[] ReadPatchKeys(BinaryReader br, int count)
        {
            var keys = new ushort[count];
            for (int i = 0; i < count; i++)
            {
                keys[i] = br.ReadUInt16();
            }
            return keys;
        }

        static void ProcessObject(BinaryReader br, int objIndex, Tuple<byte, byte> coords,
                                 byte direction, ushort patchKey, OverlayConfig config)
        {
            Console.Clear();
            Console.WriteLine($"=== Object #{objIndex} at ({coords.Item1},{coords.Item2}) ===");
            Console.WriteLine($"Direction byte: 0x{direction:X2}");

            string dirStr = DecodeDirection(direction);
            Console.WriteLine($"Directions allowed: {dirStr}");

            Console.WriteLine($"Patch key: 0x{patchKey:X4}");

            uint patchAddress = CalculatePatchAddress(patchKey, config);
            currentPatchAddress = patchAddress;
            Console.WriteLine($"Patch address: 0x{patchAddress:X4}");
            Console.WriteLine("-".PadRight(70, '-'));

            AnalyzePatchCode(br, patchAddress, objIndex, config);

            Console.WriteLine("\n" + "-".PadRight(70, '-'));
            Console.WriteLine($"Finished analyzing object #{objIndex}");
        }

        static string DecodeDirection(byte dirByte)
        {
            var directions = new List<string>();

            if ((dirByte & 0x01) != 0) directions.Add("North");
            if ((dirByte & 0x02) != 0) directions.Add("South");
            if ((dirByte & 0x04) != 0) directions.Add("East");
            if ((dirByte & 0x08) != 0) directions.Add("West");
            if ((dirByte & 0x10) != 0) directions.Add("NE");
            if ((dirByte & 0x20) != 0) directions.Add("NW");
            if ((dirByte & 0x40) != 0) directions.Add("SE");
            if ((dirByte & 0x80) != 0) directions.Add("SW");

            return directions.Count == 0 ? "None" : string.Join(", ", directions);
        }

        static uint CalculatePatchAddress(ushort key, OverlayConfig config)
        {
            uint address = (uint)(key + config.PatchBase);
            return address & 0xFFFF;
        }

        static void AnalyzePatchCode(BinaryReader br, uint patchAddress, int objIndex, OverlayConfig config)
        {
            long fileSize = br.BaseStream.Length;

            if (patchAddress >= fileSize)
            {
                Console.WriteLine($"  ERROR: Patch address 0x{patchAddress:X4} is outside file bounds (0x{fileSize:X})");
                return;
            }

            int bytesToRead = Math.Min(256, (int)(fileSize - patchAddress));
            byte[] patchData = ReadBytesAt(br, patchAddress, bytesToRead);

            Console.WriteLine("  Raw bytes (hex):");
            ShowRawBytes(patchData, patchAddress);

            // Список для сбора специальных инструкций в порядке выполнения
            var specialInstructions = new List<string>();

            // 1. Линейное дизассемблирование (БЕЗ сбора специальных инструкций)
            Console.WriteLine("\n  Linear disassembly from start:");
            ShowLinearDisassembly(br, patchAddress, false, 0, null, objIndex, config);

            // 2. Сначала анализируем косвенные пути загрузки текста
            Console.WriteLine("\n  Analyzing indirect text loading patterns...");
            var indirectTexts = new List<string>();
            try
            {
                indirectTexts = AnalyzeIndirectTextPatterns(br, patchAddress, config);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Error analyzing indirect patterns: {ex.Message}");
            }

            // 3. Полный анализ CALL инструкций со всем кодом (ТОЛЬКО здесь собираем специальные инструкции)
            Console.WriteLine("\n  Complete CALL analysis with full disassembly:");
            var analyzedCalls = new HashSet<uint>();
            AnalyzeCallsWithFullDisassembly(br, patchAddress, analyzedCalls, specialInstructions, 0, config);

            // 4. Объединяем прямые и косвенные тексты
            specialInstructions.AddRange(indirectTexts);

            // 5. Выводим все найденные специальные инструкции В ПОРЯДКЕ ВЫПОЛНЕНИЯ
            Console.WriteLine("\n  Special instructions found (in execution order):");

            // Убираем дубликаты и сортируем по адресу
            var uniqueInstructions = specialInstructions
                .Distinct()
                .OrderBy(ins => ExtractAddressForSorting(ins))
                .ToList();

            if (uniqueInstructions.Count > 0)
            {
                foreach (var instruction in uniqueInstructions)
                {
                    Console.WriteLine(instruction);
                }
            }
            else
            {
                Console.WriteLine("    No special instructions found");
            }

            Console.WriteLine("\n  Patch summary:");
            Console.WriteLine("    Object type: Determined by special instructions found above");
        }

        static void FindSpecialInInstruction(X86Instruction insn, BinaryReader br, RegisterTracker registerTracker, int depth, List<string> output, OverlayConfig config)
        {
            string prefix = new string(' ', depth * 2);
            byte[] instructionBytes = insn.Bytes;
            uint address = (uint)insn.Address;

            // 1. Прямая запись: MOV [3BD4], XXXX
            if (instructionBytes.Length >= 6 &&
                instructionBytes[0] == 0xC7 && instructionBytes[1] == 0x06 &&
                instructionBytes[2] == 0xD4 && instructionBytes[3] == 0x3B)
            {
                ushort textAddr = BitConverter.ToUInt16(instructionBytes, 4);
                ProcessTextAddress(textAddr, address, "direct MOV", prefix, br, output, config);
            }

            // 2. Запись через регистр: MOV [3BD4], AX (или другой регистр)
            else if (instructionBytes.Length >= 4 &&
                     instructionBytes[0] == 0x89 && instructionBytes[1] == 0x06 &&
                     instructionBytes[2] == 0xD4 && instructionBytes[3] == 0x3B)
            {
                // Определяем какой регистр используется
                byte modRM = instructionBytes[1];
                byte regField = (byte)((modRM >> 3) & 0x07);

                string[] regNames = { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI" };
                if (regField < regNames.Length)
                {
                    string regName = regNames[regField];
                    string line = $"{prefix}  MOV [3BD4], {regName} at 0x{address:X4}";
                    output.Add(line);

                    // Пробуем получить значение из трекера регистров
                    if (registerTracker.TryGetRegisterValue(regName, out ushort value))
                    {
                        ProcessTextAddress(value, address, $"via {regName} register", prefix, br, output, config);

                        // Если это AX и мы знаем, что он содержит комбинированный адрес
                        if (regName == "AX")
                        {
                            // Проверяем, не формировался ли этот адрес из AL и BP
                            string text = ExtractText(br, value, config);
                            if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                            {
                                output.Add($"{prefix}    ^ Text loaded into AX: \"{text}\"");
                            }
                        }
                    }
                    else
                    {
                        output.Add($"{prefix}    Note: Value in {regName} register unknown (not tracked)");
                    }
                }
            }

            // 3. Загрузка значения в 16-битный регистр
            else if (instructionBytes.Length >= 3 &&
                     (instructionBytes[0] & 0xF8) == 0xB8 &&
                     instructionBytes[0] != 0xBC && instructionBytes[0] != 0xBD)
            {
                ushort immediateValue = BitConverter.ToUInt16(instructionBytes, 1);

                // Определяем регистр по опкоду
                string regName = "r16";
                byte opcode = instructionBytes[0];
                byte regIndex = (byte)(opcode - 0xB8);

                string[] regNames = { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI" };
                if (regIndex < regNames.Length)
                {
                    regName = regNames[regIndex];
                }

                string line = $"{prefix}  MOV {regName}, 0x{immediateValue:X4} at 0x{address:X4}";
                output.Add(line);

                // Проверяем, не является ли это текстовым адресом
                ProcessTextAddress(immediateValue, address, $"loaded into {regName}", prefix, br, output, config);
            }

            // 4. Загрузка 8-битного значения в регистр (может быть частью текстового адреса)
            else if (instructionBytes.Length >= 2 &&
                     (instructionBytes[0] & 0xF8) == 0xB0)
            {
                byte immediateValue = instructionBytes[1];
                byte opcode = instructionBytes[0];
                byte regIndex = (byte)(opcode - 0xB0);

                string[] regNames8 = { "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH" };
                if (regIndex < regNames8.Length)
                {
                    string regName = regNames8[regIndex];
                    string line = $"{prefix}  MOV {regName}, 0x{immediateValue:X2} at 0x{address:X4}";
                    output.Add(line);

                    // Если это AL или AH, это может быть частью текстового адреса
                    if (regName == "AL" || regName == "AH")
                    {
                        output.Add($"{prefix}    ^ Part of possible text address in AX");
                    }
                }
            }

            // 5. Загрузка значения в BP: MOV BP, imm16
            else if (instructionBytes.Length >= 3 && instructionBytes[0] == 0xBD)
            {
                ushort immediateValue = BitConverter.ToUInt16(instructionBytes, 1);
                string line = $"{prefix}  MOV BP, 0x{immediateValue:X4} at 0x{address:X4}";
                output.Add(line);

                // Проверяем, не является ли это частью текстового адреса
                ProcessTextAddress(immediateValue, address, "loaded into BP", prefix, br, output, config);
            }

            // 6. Загрузка из памяти в AX: MOV AX, [3CB6]
            else if (instructionBytes.Length >= 5 &&
                     instructionBytes[0] == 0xA1 && instructionBytes[1] == 0xB6 && instructionBytes[2] == 0x3C)
            {
                string line = $"{prefix}  MOV AX, [3CB6] at 0x{address:X4}";
                output.Add(line);

                // Попробуем прочитать значение из памяти
                try
                {
                    ushort value = ReadUInt16At(br, 0x3CB6);
                    line = $"{prefix}    ^ [3CB6] contains: 0x{value:X4}";
                    output.Add(line);

                    ProcessTextAddress(value, address, "loaded from [3CB6]", prefix, br, output, config);
                }
                catch
                {
                    output.Add($"{prefix}    ^ Could not read [3CB6]");
                }
            }

            // 7. Запись байта в память: MOV [3CB6], AL
            else if (instructionBytes.Length >= 5 &&
                     instructionBytes[0] == 0xA2 && instructionBytes[1] == 0xB6 && instructionBytes[2] == 0x3C)
            {
                string line = $"{prefix}  MOV [3CB6], AL at 0x{address:X4}";
                output.Add(line);

                if (registerTracker.TryGetRegisterValue("AX", out ushort axValue))
                {
                    byte alValue = (byte)(axValue & 0xFF);
                    line = $"{prefix}    ^ AL contains: 0x{alValue:X2}";
                    output.Add(line);
                }
            }

            // 8. Другие специальные инструкции
            if (instructionBytes.Length >= 5 && instructionBytes[0] == 0xC6 && instructionBytes[1] == 0x06)
            {
                if (instructionBytes[2] == 0x52 && instructionBytes[3] == 0xCD)
                {
                    byte statueNum = instructionBytes[4];
                    output.Add($"{prefix}  MOV [CD52], 0x{statueNum:X2} at 0x{address:X4} (Statue #{statueNum})");
                }
                else if (instructionBytes[2] == 0xC4 && instructionBytes[3] == 0x3B)
                {
                    byte param = instructionBytes[4];
                    output.Add($"{prefix}  MOV [3BC4], 0x{param:X2} at 0x{address:X4}");
                }
                else if (instructionBytes[2] == 0xC3 && instructionBytes[3] == 0x3B)
                {
                    byte param = instructionBytes[4];
                    output.Add($"{prefix}  MOV [3BC3], 0x{param:X2} at 0x{address:X4}");
                }
            }

            // Проверяем CALL инструкции (E8 XX XX)
            if (instructionBytes.Length >= 3 && instructionBytes[0] == 0xE8)
            {
                ushort callOffset = BitConverter.ToUInt16(instructionBytes, 1);
                uint callAddr = (uint)(address + 3 + (short)callOffset);

                bool isWithinFile = callAddr < br.BaseStream.Length;
                string location = isWithinFile ? "in-file" : "external";
                output.Add($"{prefix}  CALL 0x{callAddr:X4} at 0x{address:X4} ({location})");
            }

            // Безусловный переход: JMP imm16
            if (instructionBytes.Length >= 3 && instructionBytes[0] == 0xE9)
            {
                ushort jumpOffset = BitConverter.ToUInt16(instructionBytes, 1);
                uint jumpAddr = (uint)(address + 3 + (short)jumpOffset);

                bool isWithinFile = jumpAddr < br.BaseStream.Length;
                string location = isWithinFile ? "in-file" : "external";
                output.Add($"{prefix}  JMP 0x{jumpAddr:X4} at 0x{address:X4} ({location})");
            }
        }

        static byte[] ReadBytesAt(BinaryReader br, long position, int count)
        {
            long originalPos = br.BaseStream.Position;
            br.BaseStream.Position = position;
            byte[] data = br.ReadBytes(count);
            br.BaseStream.Position = originalPos;
            return data;
        }

        static void ShowRawBytes(byte[] data, uint startAddress)
        {
            for (int i = 0; i < data.Length; i += 16)
            {
                Console.Write($"    0x{startAddress + i:X4}: ");
                for (int j = 0; j < 16 && i + j < data.Length; j++)
                {
                    Console.Write($"{data[i + j]:X2} ");
                }
                Console.WriteLine();
            }
        }

        static uint GetInstructionTargetAddress(X86Instruction insn, long fileLength)
        {
            string operand = insn.Operand ?? "";

            int hexIndex = operand.IndexOf("0x", StringComparison.OrdinalIgnoreCase);
            if (hexIndex >= 0)
            {
                string hexPart = operand.Substring(hexIndex + 2);
                hexPart = new string(hexPart.TakeWhile(c =>
                    (c >= '0' && c <= '9') ||
                    (c >= 'A' && c <= 'F') ||
                    (c >= 'a' && c <= 'f')).ToArray());

                if (uint.TryParse(hexPart, System.Globalization.NumberStyles.HexNumber, null, out uint targetAddr))
                {
                    return targetAddr;
                }
            }

            return 0;
        }

        static string ExtractText(BinaryReader br, ushort textAddress, OverlayConfig config)
        {
            try
            {
                long fileOffset = textAddress - config.TextBaseAddr;

                if (fileOffset < 0 || fileOffset >= br.BaseStream.Length)
                {
                    return $"Cannot locate text (offset: 0x{fileOffset:X}, textBase: 0x{config.TextBaseAddr:X4})";
                }

                long originalPos = br.BaseStream.Position;
                br.BaseStream.Position = fileOffset;

                var bytes = new List<byte>();
                byte b;
                int maxLength = 250;

                while ((b = br.ReadByte()) != 0 && bytes.Count < maxLength)
                {
                    bytes.Add(b);
                }

                br.BaseStream.Position = originalPos;

                if (bytes.Count == 0)
                {
                    return "(empty string)";
                }

                return DecodeText(bytes.ToArray());
            }
            catch (Exception ex)
            {
                return $"Error reading text: {ex.Message}";
            }
        }

        static string DecodeText(byte[] bytes)
        {
            var sb = new StringBuilder();

            foreach (byte b in bytes)
            {
                if (b == 0x0D)
                    sb.Append("\\r");
                else if (b == 0x0A)
                    sb.Append("\\n");
                else if (b == 0x09)
                    sb.Append("\\t");
                else if (b >= 0x20 && b <= 0x7E)
                    sb.Append((char)b);
                else if (b == 0x22)
                    sb.Append("\\\"");
                else if (b == 0x5C)
                    sb.Append("\\\\");
                else
                    sb.Append($"\\x{b:X2}");
            }

            return sb.ToString();
        }
    }
}