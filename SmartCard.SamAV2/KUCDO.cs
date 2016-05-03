using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//
using Kms2.Crypto.Utility;

namespace SmartCard.SamAV2
{
    public class KUCDO : AbstractDO
    {
        public byte KUCNo { get; set; }
        public byte RefKeyNo { get; set; }
        public byte RefKeyVer { get; set; } 
        public uint Limit { get; set; } 
        public uint CurVal { get; set; }
        public byte ProMas { get; set; }
    }
}
