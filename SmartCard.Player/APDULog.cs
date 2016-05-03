using System;
using System.Collections.Generic;
using System.Text;
using SmartCard.Pcsc;

namespace SmartCard.Player
{
    /// <summary>
    /// This class is used to log a command
    /// </summary>
    public class APDULog
    {
        //private APDUCommand m_apduCmd = null;
        //private APDUResponse m_apduResp = null;

        public APDULog(APDUCommand apduCmd, APDUResponse apduResp)
        {
            this.ApduCmd = apduCmd;
            this.ApduResp = apduResp;
        }

        #region Accessors
        public APDUCommand ApduCmd { get; set; }

        public APDUResponse ApduResp{ get; set; }
        #endregion

        public override string ToString()
        {
            return this.ApduCmd.ToString() + "\r\n" + this.ApduResp.ToString();
        }
    }

    /// <summary>
    /// List of APDULog
    /// </summary>
    public class APDULogList : List<APDULog>
    {
    }
}
