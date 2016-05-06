using System;
using System.Text;

namespace SmartCard.Pcsc
{
	/// <summary>
	/// This class represents a command APDU
	/// </summary>
	public class APDUCommand
	{
        // add by dennis, for Nxp Desfire EV1
        public bool AddLeZero { get; set; }

		/// <summary>
		/// Minimun size in bytes of an APDU command
		/// </summary>
		public const int APDU_MIN_LENGTH = 4;

		private	byte	m_bCla;
		private	byte	m_bIns;
		private	byte	m_bP1;
		private	byte	m_bP2;
		private	byte[]	m_baData;
		private	byte[]	m_bLe;

        /// <summary>
		/// Constructor
		/// </summary>
		/// <param name="bCla">Class byte</param>
		/// <param name="bIns">Instruction byte</param>
		/// <param name="bP1">Parameter P1 byte</param>
		/// <param name="bP2">Parameter P2 byte</param>
		/// <param name="baData">Data to send to the card if any, null if no data to send</param>
		/// <param name="bLe">Number of data expected, null if none</param>
        public APDUCommand( byte bCla, byte bIns, byte bP1, byte bP2, byte[] baData, byte[] baLe )
        {
            this.m_bCla = bCla;
            this.m_bIns = bIns;
            this.m_bP1 = bP1;
            this.m_bP2 = bP2;
            this.Data = baData;
            this.Le = baLe;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bCla">Class byte</param>
        /// <param name="bIns">Instruction byte</param>
        /// <param name="bP1">Parameter P1 byte</param>
        /// <param name="bP2">Parameter P2 byte</param>
        /// <param name="baData">Data to send to the card if any, null if no data to send</param>
        public APDUCommand( byte bCla, byte bIns, byte bP1, byte bP2, byte[] baData )
            : this( bCla, bIns, bP1, bP2, baData, null )
        {
        }

        //public APDUCommand(int p, int p_2, int p_3, int p_4, int p_5)
        //{
        //    // TODO: Complete member initialization
        //    this.p = p;
        //    this.p_2 = p_2;
        //    this.p_3 = p_3;
        //    this.p_4 = p_4;
        //    this.p_5 = p_5;
        //}

		/// <summary>
		/// Update the current APDU with selected parameters
		/// </summary>
		/// <param name="apduParam">APDU parameters</param>
		public void Update( APDUParam apduParam )
		{
            if( apduParam.UseClass )
            {
                this.m_bCla = apduParam.Class;
            }

            if (apduParam.UseChannel)
            {
                this.m_bIns = apduParam.Channel;
            }

            if (apduParam.UseP1)
            {
                this.m_bP1 = apduParam.P1;
            }

            if (apduParam.UseP2)
            {
                this.m_bP2 = apduParam.P2;
            }

            if( apduParam.UseData )
            {
                this.Data = apduParam.Data;
            }

            if (apduParam.UseLe)
            {
                this.Le = apduParam.Le;
            }
        }

        #region Accessors
        /// <summary>
		/// Class get property
		/// </summary>
		public byte Class
		{
			get
			{
				return m_bCla;
			}
		}


		/// <summary>
		/// Instruction get property
		/// </summary>
		public byte	Ins
		{
			get
			{
				return m_bIns;
			}
		}


		/// <summary>
		/// Parameter P1 get property
		/// </summary>
		public byte	P1
		{
			get
			{
				return m_bP1;
			}
		}


		/// <summary>
		/// Parameter P2 get property
		/// </summary>
		public byte P2
		{
			get
			{
				return m_bP2;
			}
		}


		/// <summary>
		/// Data get property
		/// </summary>
		public byte[] Data
		{
			get
			{
				return this.m_baData;
			}
            set
            {
                if (null == value)
                {
                    this.m_baData = null;
                }
                else
                {
                    this.m_baData = this.copyBa(value);
                }
            }
		}


		/// <summary>
		/// Length expected get property
		/// </summary>
		public byte[] Le
		{
			get
			{
				return this.m_bLe;
			}
            set
            {
                if( null == value )
                {
                    this.AddLeZero = false;
                    this.m_bLe = null;
                }
                else
                {
                    this.AddLeZero = true;
                    this.m_bLe = this.copyBa(value);
                } 
            }
        }
        #endregion

        /// <summary>
        /// Overrides the ToString method to format to a string the APDUCommand object
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            string strData = null;
            byte bLc = 0;
            int bP3 = ( ( null == this.m_bLe ) ? 0 : this.m_bLe[0] );    

            if( null != this.m_baData )
            {
                StringBuilder sData = new StringBuilder( this.m_baData.Length * 2);
                for(int nI = 0; nI < this.m_baData.Length; nI++)
                {
                    sData.AppendFormat("{0:X02}", this.m_baData[nI]);
                }

                strData = "Data=" + sData.ToString();
                bLc = (byte)this.m_baData.Length;
                bP3 = bLc;
            }
            
            StringBuilder strApdu = new StringBuilder();

            strApdu.AppendFormat
            (
                "Class={0:X02} Ins={1:X02} P1={2:X02} P2={3:X02} P3={4:X02} "
              , this.m_bCla, this.m_bIns, this.m_bP1, this.m_bP2, bP3
            );

            if( this.m_baData != null)
            {
                strApdu.Append(strData);
            }

            return strApdu.ToString();
        }       

        private byte[] copyBa( byte[] src )
        {
            byte[] result = null;
            if( null != src )
            {
                result = new byte[src.Length];
                src.CopyTo(result, 0);
            }
            return result;
        }
    }
}
