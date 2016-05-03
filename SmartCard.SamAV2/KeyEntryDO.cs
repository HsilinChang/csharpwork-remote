using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//
using Newtonsoft.Json;
using Kms2.Crypto.Utility;

namespace SmartCard.SamAV2
{
    public class KeyEntryDO : AbstractDO
    {
        public string KeyName { get; set; }
        public byte KeyNo { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] KeyA { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] KeyB { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] KeyC { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] DF_AID { get; set; }
        public byte DF_KEY_NO { get; set; }
        public byte CEK_NO { get; set; }
        public byte CEK_VER { get; set; }
        public byte KUC { get; set; }

        [JsonConverter(typeof(ByteArrayConvertor))]
        public byte[] SET { get; set; }
        public byte VerA { get; set; }
        public byte VerB { get; set; }
        public byte VerC { get; set; }
        public byte ExtSet { get; set; }
        public string SamMode { get; set; }
    }
}
