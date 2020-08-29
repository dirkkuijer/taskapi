<?php

require_once('db.php');
require_once('../model/Response.php');

try
{
    $writeDB = DB::connectionWriteDB();
}
catch (PDOException $ex)
{
    error_log("Connection error - ".$ex, 0);
    $response = new Response();
    $response->returnResponseError(500, "DB connection error");
}

if ($_SERVER['REQUEST_METHOD'] !== "POST")
{
    $response = new Response();
    $response->returnResponseError(405, "Request method not allowed");
}

if ($_SERVER['CONTENT_TYPE'] !== 'application/json')
{
    $response = new Response();
    $response->returnResponseError(400, "Content type header not set to JSON");
}

    $rawPostData = file_get_contents('php://input');

    if (!$jsonData = json_decode($rawPostData))
    {
        $response = new Response();
        $response->returnResponseError(400, "Request body is not valid JSON");
    }

    if (!isset($jsonData->fullname) || !isset($jsonData->username) || !isset($jsonData->password))
    {
        $response = new Response();
        $response->returnResponseError(400, "Have a look at your credentials....");
    }

    if (strlen($jsonData->fullname) < 1 || 
        strlen($jsonData->fullname) > 255 ||
        strlen($jsonData->username) < 1 ||
        strlen($jsonData->username) > 255 ||
        strlen($jsonData->password) < 1 ||
        strlen($jsonData->password) > 255 )
    {   
        $response = new Response();
        $response->returnResponseError(400, "Check the length of your credentials...");
    }

    $fullname = trim($jsonData->fullname);
    $username = trim($jsonData->username);
    $password = $jsonData->password;


    try {
        $query = $writeDB->prepare('select id from tblusers where username = :username');
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();

        if ($rowCount !== 0)
        {
            $response = new Response();
            $response->returnResponseError(409, "Username already exists");
        }

        $hased_password = password_hash($password, PASSWORD_DEFAULT);

        $query = $writeDB->prepare('insert into tblusers (fullname, username, password) values (:fullname, :username, :password)');
        $query->bindParam(':fullname', $fullname, PDO::PARAM_STR);
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->bindParam(':password', $hased_password, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();

        // empty variables for security
        // $password = $hased_password = null;
        
        
        if ($rowCount === 0)
        {
            $response = new Response();
            $response->returnResponseError(500, "There was an issue creating a user account - please try again");
        }

        $lastUserId = $writeDB->lastInsertId();
        
        $returnData = [];
        $returnData['user_id'] = $lastUserId;
        $returnData['fullname'] = $fullname;
        $returnData['username'] = $username;

        $response = new Response();
        $response->returnResponseSuccess(201, $returnData);
    }
    catch (PDOException $ex)
    {
        error_log("Database query error - ".$ex, 0);
        $response = new Response();
        $response->returnResponseError(500, "There was an issue creating a user account - please try again");
    }


?>