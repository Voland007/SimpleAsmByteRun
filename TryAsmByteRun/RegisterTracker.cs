using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Gee.External.Capstone;
using Gee.External.Capstone.X86;

namespace MMOvrAnalyzer
{
    // Класс для отслеживания состояния регистров (полностью из оригинала)
    class RegisterTracker
    {
        private Dictionary<string, ushort> registers = new Dictionary<string, ushort>();
        private Dictionary<string, string> registerSources = new Dictionary<string, string>();

        public void SetRegisterValue(string reg, ushort value, uint address, string instruction)
        {
            registers[reg.ToUpper()] = value;
            registerSources[reg.ToUpper()] = $"0x{value:X4} loaded at 0x{address:X4} via {instruction}";
        }

        public bool TryGetRegisterValue(string reg, out ushort value)
        {
            return registers.TryGetValue(reg.ToUpper(), out value);
        }

        public string GetRegisterSource(string reg)
        {
            if (registerSources.TryGetValue(reg.ToUpper(), out string source))
                return source;
            return "unknown";
        }

        public void Clear()
        {
            registers.Clear();
            registerSources.Clear();
        }

        // Новый метод для отслеживания операций с частями регистров
        public void TrackPartialRegisterOperation(string fullReg, string partialReg, byte value, uint address, string instruction)
        {
            string fullRegUpper = fullReg.ToUpper();
            string partialRegUpper = partialReg.ToUpper();

            ushort currentValue = 0;
            if (registers.TryGetValue(fullRegUpper, out ushort existingValue))
            {
                currentValue = existingValue;
            }

            if (partialRegUpper == "AL" || partialRegUpper == "AH")
            {
                // Для 8-битных операций с AX
                if (fullRegUpper == "AX")
                {
                    if (partialRegUpper == "AL")
                    {
                        currentValue = (ushort)((currentValue & 0xFF00) | value);
                    }
                    else if (partialRegUpper == "AH")
                    {
                        currentValue = (ushort)((currentValue & 0x00FF) | (value << 8));
                    }
                    registers[fullRegUpper] = currentValue;
                    registerSources[fullRegUpper] = $"{partialRegUpper} set to 0x{value:X2} at 0x{address:X4} via {instruction}";
                }
            }
        }

        // Метод для объединения значений из двух 8-битных регистров в 16-битный
        public void CombineRegisters(string destReg, string highReg, string lowReg, uint address)
        {
            string destRegUpper = destReg.ToUpper();
            string highRegUpper = highReg.ToUpper();
            string lowRegUpper = lowReg.ToUpper();

            byte highValue = 0;
            byte lowValue = 0;

            // Пробуем получить значения из трекера
            if (registers.TryGetValue(highRegUpper, out ushort highRegValue))
            {
                highValue = (byte)(highRegValue & 0xFF);
            }
            if (registers.TryGetValue(lowRegUpper, out ushort lowRegValue))
            {
                lowValue = (byte)(lowRegValue & 0xFF);
            }

            ushort combinedValue = (ushort)((highValue << 8) | lowValue);
            registers[destRegUpper] = combinedValue;
            registerSources[destRegUpper] = $"Combined from {highRegUpper}:0x{highValue:X2} and {lowRegUpper}:0x{lowValue:X2} at 0x{address:X4}";
        }
    }
}