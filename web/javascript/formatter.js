/**
 * Copyright © Mnemosyne LLC
 *
 * This file is licensed under the GPLv2.
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

function _n(num, id) {
    num %= 100;
    if (num > 19 || num < 5)
        switch (num % 10) {
            case 1: return id[0];
            case 2:
            case 3:
            case 4: return id[1];
        }
    return id[2];
}

Transmission.fmt = (function()
{
	var speed_K = 1000;
	var speed_B_str =  'Б/с';
	var speed_K_str = 'КБ/с';
	var speed_M_str = 'МБ/с';
	var speed_G_str = 'ГБ/с';
	var speed_T_str = 'ТБ/с';

	var size_K = 1000;
	var size_B_str =  'Б';
	var size_K_str = 'КБ';
	var size_M_str = 'МБ';
	var size_G_str = 'ГБ';
	var size_T_str = 'ТБ';

	var mem_K = 1024;
	var mem_B_str =   'Б';
	var mem_K_str = 'КиБ';
	var mem_M_str = 'МиБ';
	var mem_G_str = 'ГиБ';
	var mem_T_str = 'ТиБ';

	return {

		updateUnits: function(u)
		{
/*
			speed_K     = u['speed-bytes'];
			speed_K_str = u['speed-units'][0];
			speed_M_str = u['speed-units'][1];
			speed_G_str = u['speed-units'][2];
			speed_T_str = u['speed-units'][3];

			size_K     = u['size-bytes'];
			size_K_str = u['size-units'][0];
			size_M_str = u['size-units'][1];
			size_G_str = u['size-units'][2];
			size_T_str = u['size-units'][3];

			mem_K     = u['memory-bytes'];
			mem_K_str = u['memory-units'][0];
			mem_M_str = u['memory-units'][1];
			mem_G_str = u['memory-units'][2];
			mem_T_str = u['memory-units'][3];
*/
		},

		/*
		 *   Format a percentage to a string
		 */
		percentString: function(x) {
			if (x < 10.0)
				return x.toTruncFixed(2);
			else if (x < 100.0)
				return x.toTruncFixed(1);
			else
				return x.toTruncFixed(0);
		},

		/*
		 *   Format a ratio to a string
		 */
		ratioString: function(x) {
			if (x === -1)
				return '-';
			if (x === -2)
				return '&infin;';
			return this.percentString(x);
		},

		/**
		 * Formats the a memory size into a human-readable string
		 * @param {Number} bytes the filesize in bytes
		 * @return {String} human-readable string
		 */
		mem: function(bytes)
		{
			if (bytes < mem_K)
				return [ bytes, mem_B_str ].join(' ');

			var convertedSize;
			var unit;

			if (bytes < Math.pow(mem_K, 2))
			{
				convertedSize = bytes / mem_K;
				unit = mem_K_str;
			}
			else if (bytes < Math.pow(mem_K, 3))
			{
				convertedSize = bytes / Math.pow(mem_K, 2);
				unit = mem_M_str;
			}
			else if (bytes < Math.pow(mem_K, 4))
			{
				convertedSize = bytes / Math.pow(mem_K, 3);
				unit = mem_G_str;
			}
			else
			{
				convertedSize = bytes / Math.pow(mem_K, 4);
				unit = mem_T_str;
			}

			// try to have at least 3 digits and at least 1 decimal
			return convertedSize <= 9.995 ? [ convertedSize.toTruncFixed(2), unit ].join(' ')
			                              : [ convertedSize.toTruncFixed(1), unit ].join(' ');
		},

		/**
		 * Formats the a disk capacity or file size into a human-readable string
		 * @param {Number} bytes the filesize in bytes
		 * @return {String} human-readable string
		 */
		size: function(bytes)
		{
			if (bytes < size_K)
				return [ bytes, size_B_str ].join(' ');

			var convertedSize;
			var unit;

			if (bytes < Math.pow(size_K, 2))
			{
				convertedSize = bytes / size_K;
				unit = size_K_str;
			}
			else if (bytes < Math.pow(size_K, 3))
			{
				convertedSize = bytes / Math.pow(size_K, 2);
				unit = size_M_str;
			}
			else if (bytes < Math.pow(size_K, 4))
			{
				convertedSize = bytes / Math.pow(size_K, 3);
				unit = size_G_str;
			}
			else
			{
				convertedSize = bytes / Math.pow(size_K, 4);
				unit = size_T_str;
			}

			// try to have at least 3 digits and at least 1 decimal
			return convertedSize <= 9.995 ? [ convertedSize.toTruncFixed(2), unit ].join(' ')
			                              : [ convertedSize.toTruncFixed(1), unit ].join(' ');
		},

		speedBps: function(Bps)
		{
			return this.speed(this.toKBps(Bps));
		},

		toKBps: function(Bps)
		{
			return Math.floor(Bps / speed_K);
		},

		speed: function(KBps)
		{
			var speed = KBps;

			if (speed <= 999.95) // 0 KBps to 999 K
				return [ speed.toTruncFixed(0), speed_K_str ].join(' ');

			speed /= speed_K;

			if (speed <= 99.995) // 1 M to 99.99 M
				return [ speed.toTruncFixed(2), speed_M_str ].join(' ');
			if (speed <= 999.95) // 100 M to 999.9 M
				return [ speed.toTruncFixed(1), speed_M_str ].join(' ');

			// insane speeds
			speed /= speed_K;
			return [ speed.toTruncFixed(2), speed_G_str ].join(' ');
		},

		timeInterval: function(seconds)
		{


			var days    = Math.floor (seconds / 86400),
			    hours   = Math.floor ((seconds % 86400) / 3600),
			    minutes = Math.floor ((seconds % 3600) / 60),
			    seconds = Math.floor (seconds % 60),
				/*             1          2-4        5-0 & 10-19 */
			    dayNames =    ["день",    "дня",     "дней"   ],
			    hourNames =   ["час",     "часа",    "часов"  ],
			    minuteNames = ["минута",  "минуты",  "минут"  ],
			    secondNames = ["секунда", "секунды", "секунд" ],
				d = days    + ' ' + _n(days,    dayNames   ),
			    h = hours   + ' ' + _n(hours,   hourNames  ),
			    m = minutes + ' ' + _n(minutes, minuteNames),
			    s = seconds + ' ' + _n(seconds, secondNames);

			if (days) {
				if (days >= 4 || !hours)
					return d;
				return d + ', ' + h;
			}
			if (hours) {
				if (hours >= 4 || !minutes)
					return h;
				return h + ', ' + m;
			}
			if (minutes) {
				if (minutes >= 4 || !seconds)
					return m;
				return m + ', ' + s;
			}
			return s;
		},

		timestamp: function(seconds)
		{
			if (!seconds)
				return 'Н/Д';

			var myDate = new Date(seconds*1000);
			var now = new Date();

			var date = "";
			var time = "";

			var sameYear = now.getFullYear() === myDate.getFullYear();
			var sameMonth = now.getMonth() === myDate.getMonth();

			var dateDiff = now.getDate() - myDate.getDate();
			if (sameYear && sameMonth && Math.abs(dateDiff) <= 1){
				if (dateDiff === 0){
					date = "Сегодня";
				}
				else if (dateDiff === 1){
					date = "Вчера";
				}
				else{
					date = "Завтра";
				}
			}
			else{
				date = myDate.toDateString();
			}

			var hours = myDate.getHours();
			var period = "AM";
			if (hours > 12){
				hours = hours - 12;
				period = "PM";
			}
			if (hours === 0){
				hours = 12;
			}
			if (hours < 10){
				hours = "0" + hours;
			}
			var minutes = myDate.getMinutes();
			if (minutes < 10){
				minutes = "0" + minutes;
			}
			var seconds = myDate.getSeconds();
				if (seconds < 10){
					seconds = "0" + seconds;
			}

			time = [hours, minutes, seconds].join(':');

			return [date, time, period].join(' ');
		},

		ngettext: function(msgid, msgid_plural, n)
		{
			// TODO(i18n): http://doc.qt.digia.com/4.6/i18n-plural-rules.html
			return n === 1 ? msgid : msgid_plural;
		},

		countString: function(msgid, msgid_plural, n)
		{
			return [ n.toStringWithCommas(), this.ngettext(msgid,msgid_plural,n) ].join(' ');
		},

		peerStatus: function( flagStr ) 
		{ 
			var formattedFlags = []; 
			for (var i=0, flag; flag=flagStr[i]; ++i)
			{
				var explanation = null;
				switch (flag)
				{
					case "O": explanation = "Сейчас начнется скачивание"; break;
					case "D": explanation = "Загрузка с этого пира"; break;
					case "d": explanation = "Загрузка с этого пира, если нам позволят"; break;
					case "U": explanation = "Отдача этому пиру"; break;
					case "u": explanation = "Отдача этому пиру, если нас попросят"; break;
					case "K": explanation = "Пир готов отдать нам, но мы не заинтересованы"; break;
					case "?": explanation = "Мы готовы отдать пиру, но он не заинтересован"; break;
					case "E": explanation = "Соединение с шифрованием"; break;
					case "H": explanation = "Пир был обнаружен через DHT"; break;
					case "X": explanation = "Пир был обнаружен через PEX"; break;
					case "I": explanation = "Пир входящего соединения"; break;
					case "T": explanation = "Пир подключается по uTP"; break;
				}

				if (!explanation) { 
					formattedFlags.push(flag); 
				} else { 
					formattedFlags.push("<span title=\"" + flag + ': ' + explanation + "\">" + flag + "</span>"); 
				} 
			} 
			return formattedFlags.join(''); 
		}
	}
})();
