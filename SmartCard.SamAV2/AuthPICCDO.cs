using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//
using Newtonsoft.Json;
using Kms2.Crypto.Utility;

namespace SmartCard.SamAV2
{
    public class AuthPICCDO : AbstractDO
    {
        /// <summary>
        /// icash2.0 UID
        /// </summary>
        public string Uid { get; set; }
        public byte KeyNo { get; set; }
        public byte KeyVer { get; set; }
        public byte AuthMode { get; set; }
        public byte PICCKeyNo { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] DivInput { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] EncRndB { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] RndB { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] RndA { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] EncRndARndBROL8 { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] EncRndAROL8 { get; set; }
       
        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] Kxe { get; set; }
    }
}
