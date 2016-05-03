using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Kms2.Crypto.Utility;

namespace SmartCard.SamAV2
{
    public class KeyCardDO : AbstractDO
    {
        public string Merc_FLG { get; set; }
        public string Sub_Merc_Flg { get; set; }
        public string SessionKeyName { get; set; } // "SessionKey01"
        public int RandomIV_Index { get; set; } // 2967
        public int A_part_Index { get; set; } // 2869
        public string B_part_HexString { get; set; } // "60DD5684A2B8DCEB30B5B598003D2854",
        public string SessionKeyCheckSum { get; set; } // "43089A9C25A0409EBF021FBE4DEDD0EB5120DF85"
        public byte[] SessionKey { get; set; }
        public byte[] Iv { get; set; }
    }
}
