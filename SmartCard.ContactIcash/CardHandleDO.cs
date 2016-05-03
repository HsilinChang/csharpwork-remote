using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//
using SmartCard.Player;

namespace SmartCard.ContactIcash
{
    public class CardHandleDO
    {
        public string CardName { get; set; }
        public string AtrHex { get; set; }
        public string ReaderName { get; set; }
        public APDUPlayer ApduPlayer { get; set; }
    }
}
