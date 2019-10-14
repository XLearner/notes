<?php 
	/*$pattern = '/^1[3,5]\d{9}$/';  // 匹配电话号码
	// $pattern = '/(^\d{15}$)|(^\d{18}$)|(^\d{17}(\d|X|x)$)/';  // 匹配身份证号
	$str = "150992838482";
	var_dump(preg_match_all($pattern, $str, $arr));
	echo '<br/>';
	var_dump($arr);*/

	/*$parttern = '/t(.*?)st/';
	$str = "asldkftestadsftsxtst";
	var_dump(preg_match_all($parttern, $str, $arr));
	var_dump($arr);
	echo PREG_OFFSET_CAPTURE;*/

	// date_default_timezone_set('Asia/Shanghai');
	// var_dump(date('Y-m-d G:i:s'));

	// header("Content-type:image/jpeg");
/*	$img = imagecreatetruecolor(200, 200);
	$color1 = imagecolorallocate($img, 50, 50, 50);
	$color2 = imagecolorallocate($img, 150, 36, 36);
	$color3 = imagecolorallocate($img, 46, 183, 32);
	imagefill($img, 0, 0, $color3);
	imagejpeg($img, 'img/text.jpeg');
	imagedestroy($img);*/


	// 验证码
	header("Content-type:image/jpeg");
	$width = 120;
	$height = 40;
	$img = imagecreatetruecolor($width, $height);
	$colorBg = imagecolorallocate($img, rand(150, 255), rand(150, 255), rand(150, 255));
	imagefill($img, 0, 0, $colorBg);

	// $randomColor = imagecolorallocate($img, rand(150, 255), rand(150, 255), rand(150, 255));
	// 画点
	for ($i=0; $i < 200; $i++) { 
		imagesetpixel($img, rand(0,$width), rand(0,$height), imagecolorallocate($img, rand(150, 225), rand(150, 225), rand(150, 225)));
	}
	// 画线
	for ($i=0; $i < 3; $i++) { 
		imageline($img, rand(0, $width/3), rand(0, $height), rand($width*2/3, $width), rand(0, $height), imagecolorallocate($img, rand(100, 200), rand(100, 200), rand(100, 200)));
	}
	// 文字
	$fontColor = imagecolorallocate($img, rand(10, 100), rand(10, 100), rand(10, 100));
	// imagestring($img, 5, 0, 0, 'string', $fontColor);
	$font = 'distroy.ttf';
	imagettftext($img, 14, 0, 0, 10, $fontColor, $font, 'text');

	imagejpeg($img);
	imagedestroy($img);
/*
	问题： imagettftext() 无效 且不报错
*/
 ?>