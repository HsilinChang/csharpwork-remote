using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//
using Newtonsoft.Json;
using Kms2.Crypto.Utility;
using Kms2.Crypto.Common;

namespace SmartCard.SamAV2
{
    public class AuthHostDO : AbstractDO
    {
        public string Uid { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] Rnd1 { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] Rnd2 { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] RndA { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] RndB { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] Kxe { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] Ke { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] Km { get; set; }

        public byte CmdCtr { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] CmdCtrBytes 
        { 
            get
            { 
                return new byte[] { 0x00, 0x00, 0x00, CmdCtr };
            }
        }

        ///// <summary>
        ///// P1 in AV1 mode
        ///// </summary>
        //public byte AuthMode { get; set; }

        ///// <summary>
        ///// Data[2] in AV2 mode
        ///// </summary>
        //public byte HostMode { get; set; }
    }
}
