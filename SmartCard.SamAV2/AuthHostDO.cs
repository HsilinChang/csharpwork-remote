using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//
using Newtonsoft.Json;
using Kms2.Crypto.Utility;

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
