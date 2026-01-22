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
        // Класс для конфигурации файлов
        class OverlayConfig
        {
            public string FileName { get; set; }
            public ushort ObjNumBase { get; set; }  // Смещение для чтения количества объектов
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

        // Для сбора текстов из всех путей (ключ - номер пути, значение - список уникальных текстов для этого пути)
        private static Dictionary<int, HashSet<string>> allPathTexts = new Dictionary<int, HashSet<string>>();

        class AlternativePath
        {
            public int ObjectIndex { get; set; }
            public uint Address { get; set; }
            public string Condition { get; set; }
            public uint TargetAddress { get; set; }
            public bool Analyzed { get; set; }
            public int PathNumber { get; set; }
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
                filename = @"C:\GOG Games\Might and Magic 1\PORTSMIT.OVR";
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
                Console.WriteLine($"Configuration: OBJ_NUM_BASE=0x{config.ObjNumBase:X4}, TEXT_BASE_ADDR=0x{config.TextBaseAddr:X4}, PATCH_BASE=0x{config.PatchBase:X4}");
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
                        ObjNumBase = 0x386,
                        TextBaseAddr = 0xC5EC,
                        PatchBase = 0x0B7F
                    };

                case "PORTSMIT.OVR":
                    return new OverlayConfig
                    {
                        FileName = filename,
                        ObjNumBase = 0x412,
                        TextBaseAddr = 0xC560,
                        PatchBase = 0x0B7F
                    };

                default:
                    // Заглушка для неизвестных файлов - можно запросить значения у пользователя
                    Console.WriteLine($"\nUnknown file: {fileNameOnly}");
                    Console.WriteLine("Please provide configuration values:");

                    Console.Write("OBJ_NUM_BASE (hex, e.g., 0386): ");
                    string objNumBaseStr = Console.ReadLine();
                    ushort objNumBase = Convert.ToUInt16(objNumBaseStr, 16);

                    Console.Write("TEXT_BASE_ADDR (hex, e.g., C5EC): ");
                    string textBaseStr = Console.ReadLine();
                    ushort textBase = Convert.ToUInt16(textBaseStr, 16);

                    Console.Write("PATCH_BASE (hex, e.g., 0B7F): ");
                    string patchBaseStr = Console.ReadLine();
                    ushort patchBase = Convert.ToUInt16(patchBaseStr, 16);

                    return new OverlayConfig
                    {
                        FileName = filename,
                        ObjNumBase = objNumBase,
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
                            // Для условных переходов - идем по основному пути
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

        // Метод для анализа косвенных путей загрузки текста
        static HashSet<string> AnalyzeIndirectTextPatterns(BinaryReader br, uint patchAddress, OverlayConfig config)
        {
            var foundTexts = new HashSet<string>();

            // Восстанавливаем реальный путь выполнения
            var executionPath = ReconstructExecutionPath(br, patchAddress, config);

            if (executionPath.Count == 0)
            {
                return foundTexts;
            }

            // Анализируем только реальный путь выполнения
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
                                string textEntry = $"Text at 0x{combinedAddr:X4}: \"{text}\"";
                                foundTexts.Add(textEntry);
                            }
                        }
                    }
                }
            }

            return foundTexts;
        }

        // Полный анализ CALL инструкций
        static HashSet<string> AnalyzeCallsWithFullDisassembly(BinaryReader br, uint address, HashSet<uint> analyzedAddresses,
            HashSet<string> foundTexts, int depth, OverlayConfig config)
        {
            if (depth > 5)
                return foundTexts;

            if (analyzedAddresses.Contains(address))
                return foundTexts;

            analyzedAddresses.Add(address);

            // Очищаем трекер регистров при входе в новую подпрограмму
            if (depth == 0)
                registerTracker.Clear();

            long fileLength = br.BaseStream.Length;
            if (address >= fileLength)
                return foundTexts;

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

                        instructionsShown++;

                        // Ищем тексты в текущей инструкции
                        FindTextsInInstruction(insn, br, registerTracker, depth, foundTexts, config);

                        // Также отслеживаем регистры для сложных случаев
                        TrackRegisterOperations(insn, br, depth, config);

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        if (mnemonicUpper.StartsWith("CALL"))
                        {
                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                AnalyzeCallsWithFullDisassembly(br, callTarget, analyzedAddresses, foundTexts, depth + 1, config);
                            }
                        }

                        if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            return foundTexts;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
                                return foundTexts;
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
            }

            return foundTexts;
        }

        // Метод для отслеживания операций с регистрами
        static void TrackRegisterOperations(X86Instruction insn, BinaryReader br, int depth, OverlayConfig config)
        {
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

            // Загрузка непосредственного значения в 8-битный регистр
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

                // Чтение количества объектов (смещение config.ObjNumBase)
                fs.Seek(config.ObjNumBase, SeekOrigin.Begin);
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
                    globallyAnalyzedPaths.Clear();
                    allPathTexts.Clear();

                    ProcessObject(br, currentObjectIndex, coordinates[i], directions[i], patchKeys[i], config);
                }
            }
        }

        // Анализ альтернативных путей
        static void AnalyzeAlternativePaths(BinaryReader br, int objIndex, OverlayConfig config)
        {
            if (alternativePaths.Count == 0)
                return;

            // Используем while вместо for, потому что список может расширяться во время выполнения
            int currentIndex = 0;
            int pathNumber = 1;

            while (currentIndex < alternativePaths.Count)
            {
                var path = alternativePaths[currentIndex];
                if (path.Analyzed)
                {
                    currentIndex++;
                    continue;
                }

                path.PathNumber = pathNumber;
                pathNumber++;

                // Автоматически анализируем альтернативный путь
                string globalPathKey = $"{currentPatchAddress:X4}_{path.Address:X4}_{path.TargetAddress:X4}";
                if (!globallyAnalyzedPaths.Contains(globalPathKey))
                {
                    globallyAnalyzedPaths.Add(globalPathKey);

                    // Анализируем альтернативный путь
                    AnalyzeAlternativePath(br, currentPatchAddress, path.Address, path.TargetAddress,
                        objIndex, path.PathNumber, new HashSet<string>(), 0, config);

                    path.Analyzed = true;
                }

                currentIndex++;
            }
        }

        // Анализ конкретного альтернативного пути
        static void AnalyzeAlternativePath(BinaryReader br, uint patchAddress, uint jumpAddress, uint alternativeStartAddress,
            int objIndex, int pathIndex, HashSet<string> alreadyAnalyzedPaths, int recursionDepth = 0, OverlayConfig config = null)
        {
            const int MAX_RECURSION_DEPTH = 3;

            if (recursionDepth > MAX_RECURSION_DEPTH)
            {
                return;
            }

            long fileSize = br.BaseStream.Length;

            if (patchAddress >= fileSize)
            {
                return;
            }

            // Проверяем, не анализировали ли мы уже этот путь
            string pathKey = $"{jumpAddress:X4}_{alternativeStartAddress:X4}_{recursionDepth}";
            if (alreadyAnalyzedPaths.Contains(pathKey))
            {
                return;
            }
            alreadyAnalyzedPaths.Add(pathKey);

            // Список для сбора текстов в этом пути
            var foundTexts = new HashSet<string>();

            // 1. Линейное дизассемблирование альтернативного пути (с начала патча!)
            var localAlternativePaths = new List<AlternativePath>();
            ShowLinearDisassemblyWithAlternativeBranch(br, patchAddress, jumpAddress, alternativeStartAddress,
                localAlternativePaths, objIndex, 0, true, config);

            // 2. Анализ CALL инструкций в альтернативном пути (с начала патча!)
            var analyzedCalls = new HashSet<uint>();

            // Используем специальный метод для вложенных путей
            if (IsNestedPath(jumpAddress, alternativeStartAddress))
            {
                AnalyzeCallsWithNestedAlternativeBranch(br, patchAddress, jumpAddress, alternativeStartAddress,
                    analyzedCalls, foundTexts, 0, new HashSet<string>(), config);
            }
            else
            {
                // Всегда анализируем с начала патча!
                AnalyzeCallsWithAlternativeBranch(br, patchAddress, jumpAddress, alternativeStartAddress,
                    analyzedCalls, foundTexts, 0, 0, config);
            }

            // 3. Также анализируем косвенные пути загрузки текста для этого пути
            var indirectTexts = AnalyzeIndirectTextPatterns(br, patchAddress, config);
            foreach (var text in indirectTexts)
            {
                foundTexts.Add(text);
            }

            // 4. Сохраняем тексты для этого пути
            allPathTexts[pathIndex] = foundTexts;

            // 5. Анализируем ВЛОЖЕННЫЕ альтернативные пути
            if (localAlternativePaths.Count > 0 && recursionDepth < MAX_RECURSION_DEPTH)
            {
                for (int i = 0; i < localAlternativePaths.Count; i++)
                {
                    var nestedPath = localAlternativePaths[i];
                    if (nestedPath.Analyzed) continue;

                    // Проверяем, действительно ли этот путь доступен из альтернативного пути
                    if (IsTransitionReachableFromAlternativePath(br, patchAddress, jumpAddress, alternativeStartAddress, nestedPath.Address))
                    {
                        // Проверяем глобально, не анализировали ли мы уже этот путь
                        string nestedGlobalKey = $"{currentPatchAddress:X4}_{nestedPath.Address:X4}_{nestedPath.TargetAddress:X4}";
                        if (!globallyAnalyzedPaths.Contains(nestedGlobalKey))
                        {
                            globallyAnalyzedPaths.Add(nestedGlobalKey);

                            // Анализируем вложенный альтернативный путь рекурсивно
                            AnalyzeAlternativePath(br, patchAddress, nestedPath.Address, nestedPath.TargetAddress,
                                objIndex, pathIndex * 10 + i + 1, alreadyAnalyzedPaths, recursionDepth + 1, config);

                            nestedPath.Analyzed = true;
                        }
                    }
                }
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

        // Метод для проверки, является ли путь вложенным
        static bool IsNestedPath(uint jumpAddress, uint alternativeStartAddress)
        {
            return jumpAddress != 0 &&
                   alternativeStartAddress > jumpAddress &&
                   jumpAddress > 0x0090;
        }

        // Линейное дизассемблирование с альтернативной веткой
        static void ShowLinearDisassemblyWithAlternativeBranch(BinaryReader br, uint patchAddress,
            uint jumpAddress, uint alternativeStartAddress, List<AlternativePath> localAlternativePaths,
            int objIndex, int depth = 0, bool isMainAlternativeAnalysis = false, OverlayConfig config = null)
        {
            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                long fileLength = br.BaseStream.Length;
                uint currentAddress = patchAddress; // НАЧИНАЕМ С НАЧАЛА ПАТЧА!
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

                        instructionsShown++;

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // Если это тот самый условный переход - идем по альтернативной ветке
                        if (insn.Address == jumpAddress && !jumpTaken)
                        {
                            jumpTaken = true;
                            currentAddress = alternativeStartAddress;
                            break;
                        }

                        // В альтернативном пути находим ВСЕ условные переходы и добавляем их как альтернативные пути
                        if (jumpTaken && mnemonicUpper.StartsWith("J") &&
                            !mnemonicUpper.StartsWith("JMP") && !mnemonicUpper.StartsWith("JECXZ") &&
                            insn.Address != jumpAddress)
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);

                            if (jumpTarget != 0 && jumpTarget < fileLength)
                            {
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
                                    }
                                }

                                localAlternativePaths.Add(altPath);
                            }
                        }

                        if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            shouldStop = true;
                            break;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);

                            // Проверяем JMP на циклические ссылки
                            if (processedAddresses.ContainsKey(jumpTarget))
                            {
                                if (jumpTarget >= patchAddress && jumpTarget < currentAddress)
                                {
                                    shouldStop = true;
                                    break;
                                }
                            }

                            if (jumpTarget >= fileLength)
                            {
                                shouldStop = true;
                                break;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
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
            }
        }

        // Анализ CALL инструкций с альтернативной веткой
        static void AnalyzeCallsWithAlternativeBranch(BinaryReader br, uint patchAddress,
            uint jumpAddress, uint alternativeStartAddress, HashSet<uint> analyzedAddresses,
            HashSet<string> foundTexts, int depth, int callDepth = 0, OverlayConfig config = null)
        {
            const int MAX_CALL_DEPTH = 5;

            if (depth > MAX_CALL_DEPTH)
            {
                return;
            }

            if (analyzedAddresses.Contains(patchAddress))
                return;

            analyzedAddresses.Add(patchAddress);

            long fileLength = br.BaseStream.Length;
            if (patchAddress >= fileLength)
                return;

            using (var capstone = CapstoneDisassembler.CreateX86Disassembler(X86DisassembleMode.Bit16))
            {
                capstone.DisassembleSyntax = DisassembleSyntax.Intel;

                uint currentAddress = patchAddress; // ВСЕГДА НАЧИНАЕМ С НАЧАЛА ПАТЧА!
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

                        instructionsShown++;

                        // Ищем тексты в текущей инструкции
                        FindTextsInInstruction(insn, br, registerTracker, depth, foundTexts, config);

                        // Также отслеживаем регистры
                        TrackRegisterOperations(insn, br, depth, config);

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // Если это тот самый условный переход - идем по альтернативной ветке
                        if (insn.Address == jumpAddress && !jumpTaken)
                        {
                            jumpTaken = true;
                            currentAddress = alternativeStartAddress; // Переходим по альтернативной ветке
                            break;
                        }

                        if (mnemonicUpper.StartsWith("CALL"))
                        {
                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                AnalyzeCallsWithAlternativeBranch(br, callTarget, 0, 0,
                                    analyzedAddresses, foundTexts, depth + 1, callDepth + 1, config);
                            }
                        }

                        if (mnemonicUpper == "RET" || mnemonicUpper == "RETF")
                        {
                            shouldStop = true;
                            break;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
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
            }
        }

        // Анализ вложенных альтернативных веток
        static void AnalyzeCallsWithNestedAlternativeBranch(BinaryReader br, uint patchAddress,
            uint jumpAddress, uint alternativeStartAddress, HashSet<uint> analyzedAddresses,
            HashSet<string> foundTexts, int depth, HashSet<string> alreadyAnalyzedConditions = null, OverlayConfig config = null)
        {
            if (depth > 5)
            {
                return;
            }

            // Инициализируем набор уже проанализированных условий, если его нет
            if (alreadyAnalyzedConditions == null)
            {
                alreadyAnalyzedConditions = new HashSet<string>();
            }

            long fileLength = br.BaseStream.Length;

            // Создаем ключ для этого конкретного пути анализа
            string pathKey = $"{patchAddress:X4}_{jumpAddress:X4}_{alternativeStartAddress:X4}_{depth}";
            if (alreadyAnalyzedConditions.Contains(pathKey))
            {
                return;
            }
            alreadyAnalyzedConditions.Add(pathKey);

            // 1. Сначала анализируем, как достичь jumpAddress (с начала патча!)
            uint currentAddress = patchAddress; // НАЧИНАЕМ С НАЧАЛА ПАТЧА!
            bool reachedJumpAddress = false;
            int maxSteps = 100;
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
                            // Ищем тексты в инструкции CALL
                            FindTextsInInstruction(insn, br, registerTracker, depth, foundTexts, config);
                            TrackRegisterOperations(insn, br, depth, config);

                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                // Анализируем подпрограмму
                                AnalyzeCallsWithAlternativeBranch(br, callTarget, 0, 0,
                                    analyzedAddresses, foundTexts, depth + 1, 0, config);
                            }

                            currentAddress = (uint)(insn.Address + insn.Bytes.Length);
                            processedInstruction = true;
                            break;
                        }
                        // Если это условный переход, отмечаем его как необходимое условие
                        else if (mnemonic.StartsWith("J") && !mnemonic.StartsWith("JMP") && !mnemonic.StartsWith("JECXZ"))
                        {
                            // Ищем тексты в этом переходе
                            FindTextsInInstruction(insn, br, registerTracker, depth, foundTexts, config);
                            TrackRegisterOperations(insn, br, depth, config);

                            // Переходим по этому переходу (предполагаем, что он выполняется)
                            uint target = GetInstructionTargetAddress(insn, fileLength);

                            // Проверяем, не ведет ли переход к уже обработанному адресу
                            if (alreadyAnalyzedConditions.Contains($"{target:X4}_visited"))
                            {
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
                            // Обычные инструкции - ищем тексты
                            FindTextsInInstruction(insn, br, registerTracker, depth, foundTexts, config);
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

                // 2. Теперь анализируем код начиная с jumpAddress (если достигли его)
                if (reachedJumpAddress)
                {
                    // Анализируем выполнение от jumpAddress до конца
                    AnalyzeSpecificJumpExecutionWithFullCollection(br, jumpAddress, alternativeStartAddress,
                        analyzedAddresses, foundTexts, depth, "", config);
                }
                else
                {
                    // Попробуем анализировать напрямую от jumpAddress
                    AnalyzeSpecificJumpExecutionWithFullCollection(br, jumpAddress, alternativeStartAddress,
                        analyzedAddresses, foundTexts, depth, "", config);
                }
            }
        }

        // Метод для анализа конкретного перехода с полным сбором текстов
        static void AnalyzeSpecificJumpExecutionWithFullCollection(BinaryReader br, uint jumpAddress, uint alternativeStartAddress,
            HashSet<uint> analyzedAddresses, HashSet<string> foundTexts, int depth, string prefix, OverlayConfig config)
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

                        instructionsShown++;

                        // Ищем тексты и добавляем их в список
                        FindTextsInInstruction(insn, br, registerTracker, depth, foundTexts, config);
                        TrackRegisterOperations(insn, br, depth, config);

                        string mnemonic = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // Если это наш целевой переход - выполняем его
                        if (insn.Address == jumpAddress && !jumpExecuted)
                        {
                            jumpExecuted = true;
                            currentAddress = alternativeStartAddress;
                            break;
                        }

                        // Проверяем конец выполнения
                        if (mnemonic == "RET" || mnemonic == "RETF")
                        {
                            return;
                        }

                        if (mnemonic == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
                                return;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
                                currentAddress = jumpTarget;
                                break;
                            }
                        }

                        if (mnemonic.StartsWith("CALL"))
                        {
                            uint callTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (callTarget < fileLength && callTarget != 0 && !analyzedAddresses.Contains(callTarget))
                            {
                                // Анализируем подпрограмму
                                AnalyzeCallsWithAlternativeBranch(br, callTarget, 0, 0,
                                    analyzedAddresses, foundTexts, depth + 1, 0, config);
                            }
                        }

                        currentAddress = nextAddress;
                    }
                }
            }
        }

        // Вспомогательные методы для работы с данными
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
            Console.WriteLine($"\n=== Object #{objIndex} at ({coords.Item1},{coords.Item2}) ===");

            uint patchAddress = CalculatePatchAddress(patchKey, config);
            currentPatchAddress = patchAddress;

            AnalyzePatchCode(br, patchAddress, objIndex, config);
        }

        static HashSet<string> AnalyzeMainPath(BinaryReader br, uint patchAddress, OverlayConfig config)
        {
            var foundTexts = new HashSet<string>();

            // Анализируем косвенные пути загрузки текста
            var indirectTexts = AnalyzeIndirectTextPatterns(br, patchAddress, config);
            foreach (var text in indirectTexts)
            {
                foundTexts.Add(text);
            }

            // Анализируем CALL инструкции
            var analyzedCalls = new HashSet<uint>();
            AnalyzeCallsWithFullDisassembly(br, patchAddress, analyzedCalls, foundTexts, 0, config);

            return foundTexts;
        }

        static void ShowLinearDisassemblyAndCollectAlternativePaths(BinaryReader br, uint startAddress, OverlayConfig config = null)
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
                        if (processedAddresses[currentAddress] > 2)
                        {
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

                        instructionsShown++;

                        string mnemonicUpper = insn.Mnemonic.ToUpper();
                        uint nextAddress = (uint)(insn.Address + insn.Bytes.Length);

                        // В основном пути собираем ВСЕ альтернативные пути
                        if (mnemonicUpper.StartsWith("J") &&
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
                            return;
                        }

                        if (mnemonicUpper == "JMP")
                        {
                            uint jumpTarget = GetInstructionTargetAddress(insn, fileLength);
                            if (jumpTarget >= fileLength)
                            {
                                return;
                            }

                            if (jumpTarget < fileLength && jumpTarget != 0)
                            {
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
            }
        }

        static void DisplayAllPathTexts()
        {
            // Проверяем, есть ли тексты в основном пути
            bool hasMainPath = allPathTexts.ContainsKey(0) && allPathTexts[0].Count > 0;

            // Если нет текстов вообще - ничего не выводим
            if (!hasMainPath && allPathTexts.Count == 0)
                return;

            // Проверяем все альтернативные пути и собираем уникальные
            var alternativePathsToShow = new List<KeyValuePair<int, HashSet<string>>>();

            foreach (var kvp in allPathTexts.Where(k => k.Key != 0).OrderBy(k => k.Key))
            {
                if (kvp.Value.Count == 0)
                    continue;

                // Проверяем, отличается ли этот путь от основного
                bool isDifferentFromMain = !hasMainPath ||
                                           !IsSameTextSet(allPathTexts[0], kvp.Value);

                // Проверяем, отличается ли этот путь от уже добавленных альтернативных путей
                bool isDifferentFromOtherAlternatives = true;
                foreach (var existingPath in alternativePathsToShow)
                {
                    if (IsSameTextSet(existingPath.Value, kvp.Value))
                    {
                        isDifferentFromOtherAlternatives = false;
                        break;
                    }
                }

                // Если путь уникален
                if (isDifferentFromMain && isDifferentFromOtherAlternatives)
                {
                    alternativePathsToShow.Add(kvp);
                }
            }

            // Сначала выводим основной путь
            if (hasMainPath)
            {
                // Path0 выводим только если есть уникальные альтернативные пути
                bool hasUniqueAlternativePaths = alternativePathsToShow.Count > 0;

                if (hasUniqueAlternativePaths)
                {
                    Console.WriteLine($"  Path0:");
                }

                foreach (var text in allPathTexts[0].OrderBy(t => t))
                {
                    Console.WriteLine($"  {text}");
                }
            }

            // Затем выводим уникальные альтернативные пути
            foreach (var kvp in alternativePathsToShow)
            {
                Console.WriteLine($"  Path{kvp.Key}:");
                foreach (var text in kvp.Value.OrderBy(t => t))
                {
                    Console.WriteLine($"  {text}");
                }
            }
        }

        // Вспомогательный метод для сравнения двух наборов текстов
        static bool IsSameTextSet(HashSet<string> set1, HashSet<string> set2)
        {
            if (set1.Count != set2.Count)
                return false;

            // Сортируем и сравниваем как строки
            var sorted1 = set1.OrderBy(t => t).ToList();
            var sorted2 = set2.OrderBy(t => t).ToList();

            for (int i = 0; i < sorted1.Count; i++)
            {
                if (sorted1[i] != sorted2[i])
                    return false;
            }

            return true;
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
                return;
            }

            // 1. Собираем альтернативные пути из линейного дизассемблирования
            ShowLinearDisassemblyAndCollectAlternativePaths(br, patchAddress, config);

            // 2. Анализируем основной путь (линейное выполнение)
            var mainPathTexts = AnalyzeMainPath(br, patchAddress, config);

            // 3. Сохраняем тексты основного пути как Path0
            allPathTexts[0] = mainPathTexts;

            // 4. Анализируем все альтернативные пути
            AnalyzeAlternativePaths(br, objIndex, config);

            // 5. ВСЕГДА выводим результаты, даже если нет альтернативных путей
            DisplayAllPathTexts();

            Console.WriteLine("----------------------------------------");
        }

        // Метод для поиска текстов в инструкции
        static void FindTextsInInstruction(X86Instruction insn, BinaryReader br, RegisterTracker registerTracker, int depth, HashSet<string> output, OverlayConfig config)
        {
            byte[] instructionBytes = insn.Bytes;
            uint address = (uint)insn.Address;

            // 1. Прямая запись: MOV [3BD4], XXXX
            if (instructionBytes.Length >= 6 &&
                instructionBytes[0] == 0xC7 && instructionBytes[1] == 0x06 &&
                instructionBytes[2] == 0xD4 && instructionBytes[3] == 0x3B)
            {
                ushort textAddr = BitConverter.ToUInt16(instructionBytes, 4);
                string text = ExtractText(br, textAddr, config);
                if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                {
                    output.Add($"Text at 0x{textAddr:X4}: \"{text}\"");
                }
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

                    // Пробуем получить значение из трекера регистров
                    if (registerTracker.TryGetRegisterValue(regName, out ushort value))
                    {
                        string text = ExtractText(br, value, config);
                        if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                        {
                            output.Add($"Text at 0x{value:X4} (via {regName}): \"{text}\"");
                        }
                    }
                }
            }

            // 3. Загрузка значения в 16-битный регистр
            else if (instructionBytes.Length >= 3 &&
                     (instructionBytes[0] & 0xF8) == 0xB8 &&
                     instructionBytes[0] != 0xBC && instructionBytes[0] != 0xBD)
            {
                ushort immediateValue = BitConverter.ToUInt16(instructionBytes, 1);

                // Проверяем, не является ли это текстовым адресом
                string text = ExtractText(br, immediateValue, config);
                if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                {
                    output.Add($"Text at 0x{immediateValue:X4}: \"{text}\"");
                }
            }

            // 4. Загрузка значения в BP: MOV BP, imm16
            else if (instructionBytes.Length >= 3 && instructionBytes[0] == 0xBD)
            {
                ushort immediateValue = BitConverter.ToUInt16(instructionBytes, 1);
                string text = ExtractText(br, immediateValue, config);
                if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                {
                    output.Add($"Text at 0x{immediateValue:X4} (via BP): \"{text}\"");
                }
            }

            // 5. Загрузка из памяти в AX: MOV AX, [3CB6]
            else if (instructionBytes.Length >= 5 &&
                     instructionBytes[0] == 0xA1 && instructionBytes[1] == 0xB6 && instructionBytes[2] == 0x3C)
            {
                // Попробуем прочитать значение из памяти
                try
                {
                    ushort value = ReadUInt16At(br, 0x3CB6);
                    string text = ExtractText(br, value, config);
                    if (!string.IsNullOrEmpty(text) && text != "(empty string)" && !text.StartsWith("Cannot locate"))
                    {
                        output.Add($"Text at 0x{value:X4} (from [3CB6]): \"{text}\"");
                    }
                }
                catch
                {
                    // Игнорируем ошибки чтения
                }
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
                    return $"Cannot locate text (offset: 0x{fileOffset:X})";
                }

                long originalPos = br.BaseStream.Position;
                br.BaseStream.Position = fileOffset;

                var bytes = new List<byte>();
                byte b;
                int maxLength = 200;

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