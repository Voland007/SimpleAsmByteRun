using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TryAsmByteRun
{
    class OverlayConfig
    {
        public string FileName { get; set; }
        public ushort TextBaseAddr { get; set; }
        public ushort PatchBase { get; set; }
    }

   
}
