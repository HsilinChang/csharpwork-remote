
1.KeyFile裡面的是規格書內的格式
-----------------------------------------------------------------------------------------------
項次	元素名稱		資料長度	位置	型態	必要性	儲存資料目的	備註
1	Header			1		1	ASCII	M			'H'	
2	Version			4		2	BCD	M			版本識別	YYMMDD##
3	Record 筆數		2		6	BYTE	M			Little Endian, Unsign int16
							
							
	Body						
項次	元素名稱		資料長度	位置	型態	
1	UID			7		8	BYTE				SAM_AV2 	
2	Encrypted MK_Data	16		15	BYTE	
3	CHECK SUM		2		31	BYTE			
-----------------------------------------------------------------------------------------------

2.SessionKeyInfo裡面的是自訂的格式,格式如下:
{
  "Merc_FLG": "TRA",				//特約機構名稱
  "Sub_Merc_Flg": "TRA01",			//特約機構代號
  "SessionKeyName": "SessionKey01",		//SessionKey名稱
  "RandomIV_Index": 2836,
  "A_part_Index": 2556,
  "B_part_HexString": "55FBA3B8742ACC0FC11D613E04921B05",
  "SessionKeyCheckSum": "CD89F6E791B3FD77AA5C70AA34C784CBA5352869"
}


3.RandomGenerator.dll是取隨機陣列的物件,隨機陣列表數據為RndRandom.txt內(總共4096個 bytes)

呼叫Get_RandomFromIndex(int index)並帶入A_part_Index索引取得A_part陣列
呼叫Get_RandomFromIndex(int index)並帶入RandomIV_Index索引取得IV陣列

A_part陣列   XOR   B_part_HexString => SessionKey陣列

SessionKey陣列(key) + IV陣列(iv) + KeyFile內的加密DiverseKey ==作AES128==> 原始DiverseKey

SessionKeyCheckSum是用SessionKey作SHA1產生的,方便檢查SessionKey正確性