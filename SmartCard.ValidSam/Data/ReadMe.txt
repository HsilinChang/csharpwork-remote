
1.KeyFile�̭����O�W��Ѥ����榡
-----------------------------------------------------------------------------------------------
����	�����W��		��ƪ���	��m	���A	���n��	�x�s��ƥت�	�Ƶ�
1	Header			1		1	ASCII	M			'H'	
2	Version			4		2	BCD	M			�����ѧO	YYMMDD##
3	Record ����		2		6	BYTE	M			Little Endian, Unsign int16
							
							
	Body						
����	�����W��		��ƪ���	��m	���A	
1	UID			7		8	BYTE				SAM_AV2 	
2	Encrypted MK_Data	16		15	BYTE	
3	CHECK SUM		2		31	BYTE			
-----------------------------------------------------------------------------------------------

2.SessionKeyInfo�̭����O�ۭq���榡,�榡�p�U:
{
  "Merc_FLG": "TRA",				//�S�����c�W��
  "Sub_Merc_Flg": "TRA01",			//�S�����c�N��
  "SessionKeyName": "SessionKey01",		//SessionKey�W��
  "RandomIV_Index": 2836,
  "A_part_Index": 2556,
  "B_part_HexString": "55FBA3B8742ACC0FC11D613E04921B05",
  "SessionKeyCheckSum": "CD89F6E791B3FD77AA5C70AA34C784CBA5352869"
}


3.RandomGenerator.dll�O���H���}�C������,�H���}�C��ƾڬ�RndRandom.txt��(�`�@4096�� bytes)

�I�sGet_RandomFromIndex(int index)�ña�JA_part_Index���ި��oA_part�}�C
�I�sGet_RandomFromIndex(int index)�ña�JRandomIV_Index���ި��oIV�}�C

A_part�}�C   XOR   B_part_HexString => SessionKey�}�C

SessionKey�}�C(key) + IV�}�C(iv) + KeyFile�����[�KDiverseKey ==�@AES128==> ��lDiverseKey

SessionKeyCheckSum�O��SessionKey�@SHA1���ͪ�,��K�ˬdSessionKey���T��