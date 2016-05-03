using System;
using System.Collections.Generic;
using System.Text;

namespace SmartCard.Pcsc
{
    /// <summary>
    /// This class is used to update a set of parameters of an APDUCommand object
    /// </summary>
    public class APDUParam
    {
        byte
            m_bClass = 0,   //CLA
            m_bChannel = 0, //INS
            m_bP2 = 0,
            m_bP1 = 0;
        byte[] m_baData = null;
        byte[] m_nLe = null;
        bool 
            m_fUseP1 = false,
            m_fUseP2 = false,
            m_fChannel = false,
            m_fData = false,
            m_fClass = false,
            m_fLe = false;

        #region Constructors
        public APDUParam()
        {
        }

        /// <summary>
        /// Copy constructor (used for cloning)
        /// </summary>
        /// <param name="param"></param>
        public APDUParam( APDUParam param )
        {
            // Copy field
            if (null != param.m_baData)
            {
                this.m_baData = new byte[param.m_baData.Length];
                param.m_baData.CopyTo( this.m_baData, 0 );
            }
            else
            {
                this.m_baData = null;
            }
            this.m_bClass = param.m_bClass;
            this.m_bChannel = param.m_bChannel;
            this.m_bP1 = param.m_bP1;
            this.m_bP2 = param.m_bP2;
            this.m_nLe = param.m_nLe;

            // Copy flags field
            this.m_fChannel = param.m_fChannel;
            this.m_fClass = param.m_fClass;
            this.m_fData = param.m_fData;
            this.m_fLe = param.m_fLe;
            this.m_fUseP1 = param.m_fUseP1;
            this.m_fUseP2 = param.m_fUseP2;
        }

        public APDUParam( byte bClass, byte bP1, byte bP2, byte[] baData, byte[] bLe )
        {
            this.Class = bClass;
            this.P1 = bP1;
            this.P2 = bP2;
            this.Data = baData;
            this.Le = bLe;
        }
        #endregion

        /// <summary>
        /// Clones the current APDUParam instance
        /// </summary>
        /// <returns></returns>
        public APDUParam Clone()
        {
            return new APDUParam(this);
        }

        /// <summary>
        /// Resets the current instance, all flags are set to false
        /// </summary>
        public void Reset()
        {
            this.m_bClass = 0;
            this.m_bChannel = 0;
            this.m_bP1 = 0;
            this.m_bP2 = 0;
            this.m_baData = null;
            this.m_nLe = null;
            //
            this.m_fUseP1 = false;
            this.m_fUseP2 = false;
            this.m_fChannel = false;
            this.m_fData = false;
            this.m_fClass = false;
            this.m_fLe = false;
        }

        #region Flags properties
        public bool UseClass
        {
            get { return this.m_fClass; }
        }

        public bool UseChannel
        {
            get { return this.m_fChannel; }
        }

        public bool UseLe
        {
            get { return this.m_fLe; }
        }

        public bool UseData
        {
            get { return this.m_fData; }
        }

        public bool UseP1
        {
            get { return this.m_fUseP1; }
        }

        public bool UseP2
        {
            get { return this.m_fUseP2; }
        }
        #endregion

        #region Parameter properties
        public byte P1
        {
            get { return this.m_bP1; }

            set
            {
                this.m_bP1 = value;
                this.m_fUseP1 = true;
            }
        }

        public byte P2
        {
            get { return this.m_bP2; }
            set
            {
                this.m_bP2 = value;
                this.m_fUseP2 = true;
            }
        }

        public byte[] Data
        {
            get { return this.m_baData; }
            set
            {
                if( null != value )
                {
                    this.m_baData = new byte[value.Length];
                    value.CopyTo( this.m_baData, 0 );
                }
                else
                {
                    this.m_baData = null;
                }
                //this.m_baData = value;
                this.m_fData = true;
            }
        }

        public byte[] Le
        {
            get { return this.m_nLe; }
            set
            {                         
                if( null != value )
                {
                    this.m_nLe = new byte[value.Length];
                    value.CopyTo( this.m_nLe, 0 );
                    this.m_fLe = true;
                }
                else
                {
                    this.m_nLe = null;
                    this.m_fLe = false;
                }
                //this.m_nLe = value;
            }
        }

        public byte Channel
        {
            get { return this.m_bChannel; }
            set
            {
                this.m_bChannel = value;
                this.m_fChannel = true;
            }
        }

        public byte Class
        {
            get { return this.m_bClass; }
            set
            {
                this.m_bClass = value;
                this.m_fClass = true;
            }
        }
        #endregion
    }
}
