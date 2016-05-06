using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
//
using Common.Logging;
using Kms2.Crypto.Common;

namespace SmartCard.Pcsc
{
    /// <summary>
    /// CARD_STATE enumeration, used by the PC/SC function SCardGetStatusChanged
    /// </summary>
    enum CARD_STATE
    {
        UNAWARE = 0x00000000,
        IGNORE = 0x00000001,
        CHANGED = 0x00000002,
        UNKNOWN = 0x00000004,
        UNAVAILABLE = 0x00000008,
        EMPTY = 0x00000010,
        PRESENT = 0x00000020,
        ATRMATCH = 0x00000040,
        EXCLUSIVE = 0x00000080,
        INUSE = 0x00000100,
        MUTE = 0x00000200,
        UNPOWERED = 0x00000400
    }

	/// <summary>
	/// Wraps the SCARD_IO_STRUCTURE
    ///  
	/// </summary>
	[StructLayout(LayoutKind.Sequential)]
	public struct	SCard_IO_Request
	{
		public UInt32	m_dwProtocol;
		public UInt32	m_cbPciLength;
	}


    /// <summary>
    /// Wraps the SCARD_READERSTATE structure of PC/SC
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct SCard_ReaderState
    {
        public string m_szReader;
        public IntPtr m_pvUserData;
        public UInt32 m_dwCurrentState;
        public UInt32 m_dwEventState;
        public UInt32 m_cbAtr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=32)]
        public byte[] m_rgbAtr;
    }
    
	/// <summary>
	/// Implementation of ICard using native (P/Invoke) interoperability for PC/SC
	/// </summary>
	public class CardNative : CardBase
	{
        private static readonly ILog log = LogManager.GetLogger(typeof(CardNative));
        private IntPtr m_hContext = IntPtr.Zero;
        private IntPtr m_hCard = IntPtr.Zero;
		private	UInt32	m_nProtocol = (uint) PROTOCOL.T1;
		private	int	m_nLastError = 0;
        const int SCARD_S_SUCCESS = 0;

        public HexConverter HexConverter { private get; set; }

		#region PCSC_FUNCTIONS
        /// <summary>
        /// Native SCardGetStatusChanged from winscard.dll
        /// </summary>
        /// <param name="hContext"></param>
        /// <param name="dwTimeout"></param>
        /// <param name="rgReaderStates"></param>
        /// <param name="cReaders"></param>
        /// <returns></returns>
        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardGetStatusChange
        (
            IntPtr hContext,
            UInt32 dwTimeout,
            [In,Out] SCard_ReaderState[] rgReaderStates,
            UInt32 cReaders
        );

		/// <summary>
		/// Native SCardListReaders function from winscard.dll
		/// </summary>
		/// <param name="hContext"></param>
		/// <param name="mszGroups"></param>
		/// <param name="mszReaders"></param>
		/// <param name="pcchReaders"></param>
		/// <returns></returns>
		[DllImport("winscard.dll", SetLastError=true)]
        internal static extern int SCardListReaders
        (
            IntPtr hContext,
			[MarshalAs(UnmanagedType.LPTStr)] string mszGroups,
			IntPtr mszReaders,
            out UInt32 pcchReaders
        );

		/// <summary>
		/// Native SCardEstablishContext function from winscard.dll
		/// </summary>
		/// <param name="dwScope"></param>
		/// <param name="pvReserved1"></param>
		/// <param name="pvReserved2"></param>
		/// <param name="phContext"></param>
		/// <returns></returns>
		[DllImport("winscard.dll", SetLastError=true)]
		internal static	extern	int	SCardEstablishContext
        (
            UInt32 dwScope,
			IntPtr pvReserved1,
			IntPtr pvReserved2,
			IntPtr phContext
        );

		/// <summary>
		/// Native SCardReleaseContext function from winscard.dll
		/// </summary>
		/// <param name="hContext"></param>
		/// <returns></returns>
		[DllImport("winscard.dll", SetLastError=true)]
        internal static extern int SCardReleaseContext(IntPtr hContext);

        /// <summary>
        /// Native SCardIsValidContext function from winscard.dll
        /// </summary>
        /// <param name="hContext"></param>
        /// <returns></returns>
        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardIsValidContext(IntPtr hContext);

		/// <summary>
		/// Native SCardConnect function from winscard.dll
		/// </summary>
		/// <param name="hContext"></param>
		/// <param name="szReader"></param>
		/// <param name="dwShareMode"></param>
		/// <param name="dwPreferredProtocols"></param>
		/// <param name="phCard"></param>
		/// <param name="pdwActiveProtocol"></param>
		/// <returns></returns>
		[DllImport("winscard.dll", SetLastError=true, CharSet=CharSet.Auto)]
        internal static extern int SCardConnect
        (
            IntPtr hContext,
			[MarshalAs(UnmanagedType.LPTStr)] string szReader,
			UInt32	dwShareMode, 
			UInt32	dwPreferredProtocols,
			IntPtr	phCard, 
			IntPtr	pdwActiveProtocol
        );

		/// <summary>
		/// Native SCardDisconnect function from winscard.dll
		/// </summary>
		/// <param name="hCard"></param>
		/// <param name="dwDisposition"></param>
		/// <returns></returns>
		[DllImport("winscard.dll", SetLastError=true)]
        internal static extern int SCardDisconnect
        (
            IntPtr hCard,
			UInt32 dwDisposition
        );

		/// <summary>
		/// Native SCardTransmit function from winscard.dll
		/// </summary>
		/// <param name="hCard"></param>
		/// <param name="pioSendPci"></param>
		/// <param name="pbSendBuffer"></param>
		/// <param name="cbSendLength"></param>
		/// <param name="pioRecvPci"></param>
		/// <param name="pbRecvBuffer"></param>
		/// <param name="pcbRecvLength"></param>
		/// <returns></returns>
        //[DllImport("winscard.dll", SetLastError=true)]
        //internal static extern int SCardTransmit
        //(
        //    IntPtr hCard,
        //    [In] ref SCard_IO_Request pioSendPci,
        //    byte[] pbSendBuffer,
        //    UInt32 cbSendLength,
        //    IntPtr pioRecvPci,
        //    [Out] byte[] pbRecvBuffer,
        //    out UInt32 pcbRecvLength
        //);
        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardTransmit
        (
            IntPtr hCard,
            [In] ref SCard_IO_Request pioSendPci,
            IntPtr pbSendBuffer,
            UInt32 cbSendLength,
            IntPtr pioRecvPci,
            [Out] IntPtr pbRecvBuffer,
            out UInt32 pcbRecvLength
        );

        /// <summary>
        /// Native SCardBeginTransaction function of winscard.dll
        /// </summary>
        /// <param name="hContext"></param>
        /// <returns></returns>
        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardBeginTransaction(IntPtr hContext);

        /// <summary>
        /// Native SCardEndTransaction function of winscard.dll
        /// </summary>
        /// <param name="hContext"></param>
        /// <returns></returns>
        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardEndTransaction(IntPtr hContext, UInt32 dwDisposition);

        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardGetAttrib
        (
            IntPtr hCard,
            UInt32 dwAttribId,
            [Out] byte[] pbAttr,
            out UInt32 pcbAttrLen
        );

        #endregion WINSCARD_FUNCTIONS

		/// <summary>
		/// Default constructor
		/// </summary>
		public CardNative()
		{
		}

		/// <summary>
		/// Object destruction
		/// </summary>
		~CardNative()
		{
			Disconnect(DISCONNECT.Unpower);

			ReleaseContext();
		}

		#region ICard Members

		/// <summary>
		/// Wraps the PCSC function
		/// LONG SCardListReaders(SCARDCONTEXT hContext, 
		///		LPCTSTR mszGroups, 
		///		LPTSTR mszReaders, 
		///		LPDWORD pcchReaders 
		///	);
		/// </summary>
		/// <returns>A string array of the readers</returns>
		public override string[] ListReaders()
		{			
            string[] sListReaders = null;
            UInt32 pchReaders = 0;
			IntPtr szListReaders = IntPtr.Zero;
            //
            EstablishContext(SCOPE.User);            
            //
			m_nLastError = SCardListReaders( this.m_hContext, null, szListReaders, out pchReaders);
			if (m_nLastError == 0)
			{
				szListReaders = Marshal.AllocHGlobal((int)pchReaders);
				m_nLastError = SCardListReaders( this.m_hContext, null, szListReaders, out pchReaders);
				if (m_nLastError == 0)
				{
					char[] caReadersData = new char[pchReaders];
					int	nbReaders = 0; // count of readers
					for (int nI = 0; nI < pchReaders; nI++)
					{
						caReadersData[nI] = (char) Marshal.ReadByte(szListReaders, nI);

                        if (caReadersData[nI] == 0)
                        {
                            nbReaders++;
                        }
					}

					// Remove last 0
					--nbReaders;

					if (nbReaders != 0)
					{
						sListReaders = new string[nbReaders];
						char[] caReader = new char[pchReaders];
						int	nIdx = 0;
						int	nIdy = 0;
						int	nIdz = 0;
						// Get the nJ string from the multi-string

						while( nIdx < pchReaders - 1 )
						{
							caReader[nIdy] = caReadersData[nIdx];
							if (caReader[nIdy] == 0)
							{
								sListReaders[nIdz] = new string(caReader, 0, nIdy);
								++nIdz;
								nIdy = 0;
								caReader = new char[pchReaders];
							}
							else
								++nIdy;

							++nIdx;
						}
					}

				}

				Marshal.FreeHGlobal(szListReaders);
			}
			ReleaseContext();
			return sListReaders;
		}

		/// <summary>
		/// Wraps the PCSC function 
		/// LONG SCardEstablishContext(
		///		IN DWORD dwScope,
		///		IN LPCVOID pvReserved1,
		///		IN LPCVOID pvReserved2,
		///		OUT LPSCARDCONTEXT phContext
		///	);
		/// </summary>
		/// <param name="Scope"></param>
		public void EstablishContext(SCOPE Scope)
		{
			IntPtr hContext = Marshal.AllocHGlobal(Marshal.SizeOf(this.m_hContext));
            //
			m_nLastError = SCardEstablishContext((uint) Scope, IntPtr.Zero, IntPtr.Zero, hContext);
			if (m_nLastError != 0)
            {
                Marshal.FreeHGlobal(hContext);
				string msg = "SCardEstablishContext error: " + this.getErrorMsg( m_nLastError );
				throw new Exception(msg);
			}
            this.m_hContext = Marshal.ReadIntPtr(hContext);
            //log.Debug( m => m( "hContext:[{0}]", this.m_hContext.ToInt64()));
            //
			Marshal.FreeHGlobal(hContext);
		}


		/// <summary>
		/// Wraps the PCSC function
		/// LONG SCardReleaseContext(
		///		IN SCARDCONTEXT hContext
		///	);
		/// </summary>
		public void ReleaseContext()
		{
			if (SCardIsValidContext( this.m_hContext ) == SCARD_S_SUCCESS)
			{

				m_nLastError = SCardReleaseContext(this.m_hContext);

				if (m_nLastError != 0)
				{
					string	msg = "SCardReleaseContext error: " + this.getErrorMsg( m_nLastError );
                    //throw new Exception(msg);
                    log.Error(m => m("{0}", msg));
				}

                this.m_hContext = IntPtr.Zero;
			}
		}

		/// <summary>
		///  Wraps the PCSC function
		///  LONG SCardConnect(
		///		IN SCARDCONTEXT hContext,
		///		IN LPCTSTR szReader,
		///		IN DWORD dwShareMode,
		///		IN DWORD dwPreferredProtocols,
		///		OUT LPSCARDHANDLE phCard,
		///		OUT LPDWORD pdwActiveProtocol
		///	);
		/// </summary>
		/// <param name="Reader"></param>
		/// <param name="ShareMode"></param>
		/// <param name="PreferredProtocols"></param>
		public override void Connect(string Reader, SHARE ShareMode, PROTOCOL PreferredProtocols)
		{
			EstablishContext(SCOPE.User);
            //
			IntPtr hCard = Marshal.AllocHGlobal( Marshal.SizeOf(this.m_hCard) );
			IntPtr pProtocol = Marshal.AllocHGlobal( Marshal.SizeOf( this.m_nProtocol ) );
            //            
			m_nLastError = SCardConnect
            (
                this.m_hContext, 
				Reader, 
				(uint)ShareMode, 
				(uint)PreferredProtocols, 
				hCard,
				pProtocol
            );

			if (m_nLastError != 0)
			{

                Marshal.FreeHGlobal(hCard);
                Marshal.FreeHGlobal(pProtocol);
                //
				string msg = "SCardConnect error: " + this.getErrorMsg( m_nLastError );
				throw new Exception(msg);
			}

            this.m_hCard = Marshal.ReadIntPtr(hCard);
			this.m_nProtocol = (uint)Marshal.ReadInt32(pProtocol);

			Marshal.FreeHGlobal(hCard);
			Marshal.FreeHGlobal(pProtocol);
		}

		/// <summary>
		/// Wraps the PCSC function
		///	LONG SCardDisconnect(
		///		IN SCARDHANDLE hCard,
		///		IN DWORD dwDisposition
		///	);
		/// </summary>
		/// <param name="Disposition"></param>
		public override void Disconnect(DISCONNECT Disposition)
		{
            if ( SCardIsValidContext( this.m_hContext ) == SCARD_S_SUCCESS)
			{ 
				m_nLastError = SCardDisconnect( this.m_hCard, (uint)Disposition );
                this.m_hCard = IntPtr.Zero;

				if (m_nLastError != 0)
				{                    
					string msg = "SCardDisconnect error: " + this.getErrorMsg(m_nLastError);
                    log.Error( m => m( "{0}", msg ) );
					//throw new Exception(msg);
				}
			}
            ReleaseContext();
		}

		/// <summary>
		/// Wraps the PCSC function
		/// LONG SCardTransmit(
		///		SCARDHANDLE hCard,
		///		LPCSCARD_I0_REQUEST pioSendPci,
		///		LPCBYTE pbSendBuffer,
		///		DWORD cbSendLength,
		///		LPSCARD_IO_REQUEST pioRecvPci,
		///		LPBYTE pbRecvBuffer,
		///		LPDWORD pcbRecvLength
		///	);
		/// </summary>
		/// <param name="ApduCmd">APDUCommand object with the APDU to send to the card</param>
		/// <returns>An APDUResponse object with the response from the card</returns>
		public override APDUResponse Transmit(APDUCommand apduCmd)
		{			
			byte[]	apduBuffer = null;
            
            // Allocate max apdu response 
            //new byte[ApduCmd.Le + APDUResponse.SW_LENGTH];
            byte[] apduResponse = new byte[byte.MaxValue + APDUResponse.SW_LENGTH];

            // Same as length of ApduResponse
            //uint	RecvLength = (uint) (ApduCmd.Le + APDUResponse.SW_LENGTH);
            uint RecvLength = (uint)(apduResponse.Length);

			SCard_IO_Request ioRequest = new SCard_IO_Request();
			ioRequest.m_dwProtocol = this.m_nProtocol;
			ioRequest.m_cbPciLength = 8;
            //
            int leSize;
            if( null != apduCmd.Le )
            {
                leSize = apduCmd.Le.Length;
            }
            else if( apduCmd.AddLeZero )
            {
                leSize = 1;
            }
            else
            {
                leSize = 0;
            }
            //
			// Build the command APDU
			if( apduCmd.Data == null )
			{
                // For NXP style add Le => 0x00 to tail
				//ApduBuffer = new byte[APDUCommand.APDU_MIN_LENGTH + ((ApduCmd.Le != 0) ? 1 : 0)];
                apduBuffer = new byte[ APDUCommand.APDU_MIN_LENGTH + leSize ];
                //ApduBuffer[ApduBuffer.Length-1] = (byte)ApduCmd.Le;
			}
			else
			{
                apduBuffer = new byte[ APDUCommand.APDU_MIN_LENGTH + 1 + apduCmd.Data.Length + leSize ];
                apduBuffer[ APDUCommand.APDU_MIN_LENGTH ] = (byte)apduCmd.Data.Length; // Lc
                for (int nI = 0; nI < apduCmd.Data.Length; nI++)
                {
                    apduBuffer[APDUCommand.APDU_MIN_LENGTH + 1 + nI] = apduCmd.Data[nI];
                }				
			}

			apduBuffer[0] = apduCmd.Class;
			apduBuffer[1] = apduCmd.Ins;
			apduBuffer[2] = apduCmd.P1;
			apduBuffer[3] = apduCmd.P2;

            if ( null != apduCmd.Le ) 
            {
                for(int i = apduCmd.Le.Length; i > 0; i--)
                {
                    apduBuffer[ apduBuffer.Length - i ] = apduCmd.Le[apduCmd.Le.Length - i];
                }
            }
            else if( apduCmd.AddLeZero )
            {
                apduBuffer[ apduBuffer.Length - 1 ] = 0;
            }

            log.Debug( m => m( "CAPDU:[{0}]", this.HexConverter.Bytes2Hex(apduBuffer) ) ); 
            //
            // pin apduBuffer
            GCHandle gchApduBuffer = GCHandle.Alloc( apduBuffer, GCHandleType.Pinned );
            IntPtr pApduBuffer = Marshal.UnsafeAddrOfPinnedArrayElement( apduBuffer, 0 );
            // pin apduResponse
            GCHandle gchApduResponse = GCHandle.Alloc( apduResponse, GCHandleType.Pinned);
            IntPtr pApduResponse = Marshal.UnsafeAddrOfPinnedArrayElement( apduResponse, 0 );
            //
            m_nLastError = SCardTransmit
            ( 
                this.m_hCard,
                ref ioRequest,
                pApduBuffer,
                (uint)apduBuffer.Length,
                IntPtr.Zero, 
                pApduResponse, 
                out RecvLength 
            );
            //log.Debug( m => m( "RAPDU Length: {0}", RecvLength ) );

            if (m_nLastError != 0)
            {                
                gchApduBuffer.Free();
                gchApduResponse.Free();
                string msg = "SCardTransmit error: " + this.getErrorMsg( m_nLastError );
                throw new Exception(msg);
            }
            
			byte[] apduResponseData = new byte[RecvLength];

            for (int nI = 0; nI < RecvLength; nI++)
            {
                apduResponseData[nI] = apduResponse[nI];
            }
            //log.Debug( m => m( "RAPDU:[{0}]", this.HexConverter.Bytes2Hex(apduData) ) );
            gchApduBuffer.Free();
            gchApduResponse.Free();
			return new APDUResponse( apduResponseData );
		}


        /// <summary>
        /// Wraps the PSCS function
        /// LONG SCardBeginTransaction(
        ///     SCARDHANDLE hCard
        //  );
        /// </summary>
        public override void BeginTransaction()
        { 
            if (SCardIsValidContext( this.m_hContext ) == SCARD_S_SUCCESS)
            {
                m_nLastError = SCardBeginTransaction( this.m_hCard );
                if (m_nLastError != 0)
                {
                    string msg = "SCardBeginTransaction error: " + this.getErrorMsg( m_nLastError );
                    throw new Exception(msg);
                }
            }
        }

        /// <summary>
        /// Wraps the PCSC function
        /// LONG SCardEndTransaction(
        ///     SCARDHANDLE hCard,
        ///     DWORD dwDisposition
        /// );
        /// </summary>
        /// <param name="Disposition">A value from DISCONNECT enum</param>
        public override void EndTransaction(DISCONNECT Disposition)
        {
            if (SCardIsValidContext(this.m_hContext) == SCARD_S_SUCCESS)
            {
                m_nLastError = SCardEndTransaction(this.m_hCard, (UInt32)Disposition);
                if (m_nLastError != 0)
                {
                    string msg = "SCardEndTransaction error: " + this.getErrorMsg( m_nLastError );
                    throw new Exception(msg);
                }
            }
        }

        /// <summary>
        /// Gets the attributes of the card
        /// </summary>
        /// <param name="AttribId">Identifier for the Attribute to get</param>
        /// <returns>Attribute content</returns>
        public override byte[] GetAttribute(UInt32 AttribId)
        {
            byte[] attr = null;
            UInt32 attrLen = 0;

            m_nLastError = SCardGetAttrib( this.m_hCard, AttribId, attr, out attrLen);
            if (m_nLastError == 0)
            {
                if (attrLen != 0)
                {
                    attr = new byte[attrLen];
                    m_nLastError = SCardGetAttrib( this.m_hCard, AttribId, attr, out attrLen );
                    if (m_nLastError != 0)
                    {
                        string msg = "SCardGetAttr error: " + this.getErrorMsg(m_nLastError);
                        throw new Exception(msg);
                    }
                }
            }
            else
            {
                string msg = "SCardGetAttr error: " + this.getErrorMsg(m_nLastError);
                throw new Exception(msg);
            }

            return attr;
        }
        #endregion

        /// <summary>
        /// This function must implement a card detection mechanism.
        /// 
        /// When card insertion is detected, it must call the method CardInserted()
        /// When card removal is detected, it must call the method CardRemoved()
        /// 
        /// </summary>
        protected override void RunCardDetection(object Reader)
        {
            bool bFirstLoop = true;
            IntPtr hContext = IntPtr.Zero;    // Local context
            IntPtr phContext;

            phContext = Marshal.AllocHGlobal(Marshal.SizeOf(hContext));

            if (SCardEstablishContext((uint) SCOPE.User, IntPtr.Zero, IntPtr.Zero, phContext) == 0)
            {
                hContext = Marshal.ReadIntPtr(phContext);
                Marshal.FreeHGlobal(phContext);

                UInt32 nbReaders = 1;
                SCard_ReaderState[] readerState = new SCard_ReaderState[nbReaders];

                readerState[0].m_dwCurrentState = (UInt32) CARD_STATE.UNAWARE;
                readerState[0].m_szReader = (string)Reader;

                UInt32 eventState;
                UInt32 currentState = readerState[0].m_dwCurrentState;

                // Card detection loop
                do
                {
                    if (SCardGetStatusChange(hContext, WAIT_TIME
                        , readerState, nbReaders) == 0)
                    {
                        eventState = readerState[0].m_dwEventState;
                        currentState = readerState[0].m_dwCurrentState;

                        // Check state
                        if (((eventState & (uint) CARD_STATE.CHANGED) == (uint) CARD_STATE.CHANGED) && !bFirstLoop)    
                        {
                            // State has changed
                            if ((eventState & (uint) CARD_STATE.EMPTY) == (uint) CARD_STATE.EMPTY)
                            {
                                // There is no card, card has been removed -> Fire CardRemoved event
                                CardRemoved((string)Reader);
                            }

                            if (((eventState & (uint)CARD_STATE.PRESENT) == (uint)CARD_STATE.PRESENT) && 
                                ((eventState & (uint) CARD_STATE.PRESENT) != (currentState & (uint) CARD_STATE.PRESENT)))
                            {
                                // There is a card in the reader -> Fire CardInserted event
                                CardInserted((string)Reader);
                            }

                            if ((eventState & (uint) CARD_STATE.ATRMATCH) == (uint) CARD_STATE.ATRMATCH)
                            {
                                // There is a card in the reader and it matches the ATR we were expecting-> Fire CardInserted event
                                CardInserted((string)Reader);
                            }
                        }

                        // The current stateis now the event state
                        readerState[0].m_dwCurrentState = eventState;

                        bFirstLoop = false;
                    }

                    Thread.Sleep(100);

                    if (m_bRunCardDetection == false)
                        break;
                }
                while (true);    // Exit on request
            }
            else
            {
                Marshal.FreeHGlobal(phContext);
                throw new Exception("PC/SC error");
            }

            SCardReleaseContext(hContext);
        }

        //例外的Error code處理
        private string getErrorMsg(int errCode)
        {
            string cErrString = null;
            uint uErrCode = (uint)errCode;
            switch (uErrCode)
            {
                case 0x80100001:
                    cErrString = "Internal Error";
                    break;
                case 0x80100002:
                    cErrString = "Cancelled";
                    break;
                case 0x80100003:
                    cErrString = "Invalid Handle";
                    break;
                case 0x80100004:
                    cErrString = "Invalid Parameter";
                    break;
                case 0x80100005:
                    cErrString = "Invalid Target";
                    break;
                case 0x80100006:
                    cErrString = "No Memory";
                    break;
                case 0x80100007:
                    cErrString = "Waited Too Long";
                    break;
                case 0x80100008:
                    cErrString = "Insufficient Buffer";
                    break;
                case 0x80100009:
                    cErrString = "Unknown Reader";
                    break;
                case 0x8010000A:
                    cErrString = "Timeout";
                    break;
                case 0x8010000B:
                    cErrString = "Sharing Violation";
                    break;
                case 0x8010000C:
                    cErrString = "No Smart Card";
                    break;
                case 0x8010000D:
                    cErrString = "Unknown Card";
                    break;
                case 0x8010000E:
                    cErrString = "Can't Dispose";
                    break;
                case 0x8010000F:
                    cErrString = "Proto Mismatch";
                    break;
                case 0x80100010:
                    cErrString = "Not Ready";
                    break;
                case 0x80100011:
                    cErrString = "Invalid Value";
                    break;
                case 0x80100012:
                    cErrString = "System Cancelled";
                    break;
                case 0x80100013:
                    cErrString = "Comm Error";
                    break;
                case 0x80100014:
                    cErrString = "Unknown Error";
                    break;
                case 0x80100015:
                    cErrString = "Invalid ATR";
                    break;
                case 0x80100016:
                    cErrString = "Not Transacted";
                    break;
                case 0x80100017:
                    cErrString = "Reader Unavailable";
                    break;
                case 0x80100018:
                    cErrString = "Shutdown";
                    break;
                case 0x80100019:
                    cErrString = "PCI Too Small";
                    break;
                case 0x8010001A:
                    cErrString = "Reader Unsupported";
                    break;
                case 0x8010001B:
                    cErrString = "Duplicate Reader";
                    break;
                case 0x8010001C:
                    cErrString = "Card Unsupported";
                    break;
                case 0x8010001D:
                    cErrString = "No Service";
                    break;
                case 0x8010001E:
                    cErrString = "Service Stopped";
                    break;
                case 0x8010001F:
                    cErrString = "Unsupported Feature";
                    break;
                case 0x80100020:
 	                cErrString = "Card Installation Error";
                    break;
                case 0x80100021:
                    cErrString = "Card Creation Order Error";
                    break;
                case 0x80100023:
 	                cErrString = "Directory Not Found";
                    break;
                case 0x80100024:
                    cErrString = "File Not Found";
                    break;
                case 0x80100025:
 	                cErrString = "No Directory";
                    break;
                case 0x80100026:
 	                cErrString = "No File";
                    break;
                case 0x80100027:
 	                cErrString = "File Access Denied";
                    break;
                case 0x80100028:
 	                cErrString = "Not Enough Memory";
                    break;
                case 0x80100029:
 	                cErrString = "File Seek Error";
                    break;
                case 0x8010002A:
 	                cErrString = "Invalid Pin";
                    break;
                case 0x8010002B:
 	                cErrString = "Unknow Res Mng";
                    break;
                case 0x8010002C:
 	                cErrString = "No Such Certificate";
                    break;
                case 0x8010002D:
 	                cErrString = "Certificate Unavaliable";
                    break;
                case 0x8010002E:
 	                cErrString = "No Readers Available";
                    break;
                case 0x8010002F:
 	                cErrString = "Comm Data Lost";
                    break;
                case 0x80100030:
 	                cErrString = "No Key Container";
                    break;
                case 0x80100031:
 	                cErrString = "Server Too Busy";
                    break;
                case 0x80100065:
                    cErrString = "Unsupported Card";
                    break;
                case 0x80100066:
                    cErrString = "Unresponsive Card";
                    break;
                case 0x80100067:
                    cErrString = "Unpowered Card";
                    break;
                case 0x80100068:
                    cErrString = "Reset Card";
                    break;
                case 0x80100069:
                    cErrString = "Removed Card";
                    break;
                case 0x8010006A:
                    cErrString = "Security Violation";
                    break;
                case 0x8010006B:
                    cErrString = "Wrong Pin";
                    break;
                case 0x8010006C:
                    cErrString = "Pin Blocked";
                    break;
                case 0x8010006D:
                    cErrString = "EOF Reached";
                    break;
                case 0x8010006E:
 	                cErrString = "Cancel by User";
                    break;
                case 0x8010006F:
 	                cErrString = "Card Not Authenticated";
                    break;
                default:
                    cErrString = "Unknown PC/SC Error Code - No Further Information Is Available";
                    break;
            }
            return String.Format("[{0:X08}]", uErrCode) + cErrString;
        }
	}
}