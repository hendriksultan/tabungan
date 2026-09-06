<?php
	defined('BASEPATH') OR exit('No direct script access allowed');
?>

<!DOCTYPE html>
<html lang="en">

<head>

	<title><?= $heading ?></title>

	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->

	<!-- Bootstrap -->
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">

	<!-- Custom stlylesheet -->
	<link type="text/css" rel="stylesheet" href="css/style.css" />

	<style>
		body {
			background-color: #f1f1f1;
		}

		.vertical-center {
			min-height: 100%;
			min-height: 100vh;

			display: flex;
			align-items: center;
		}
	</style>

</head>

<body>

	<div class="vertical-center">
		<div class="container">
			<div id="notfound" class="text-center ">
				<h1>😮</h1>
				<h2>Oops! Page Not Be Found</h2>
				<p>Sorry but the page you are looking for does not exist.</p>
				<button class="btn btn-primary btn-sm" onclick="history.back(-1)">
					Back to homepage
				</button> | 
				<a href="https://smartitplus.com/" target="blank">SmartDev</a> <?= date('Y') ?>
			</div>
		</div>
	</div>

</body>

</html>