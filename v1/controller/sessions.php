<?php

require_once('db.php');
require_once('../model/Response.php');

try
{
    $writeDB = DB::connectionWriteDB();
}
catch (PDOException $ex)
{   
    error_log('Connection error - '.$ex, 0);
    $response = new Response();
    $response->returnResponseError(500, "DB connection error");
}


if (array_key_exists("sessionid", $_GET))
{
    $sessionid = $_GET['sessionid'];
    
    if ($sessionid == '' || !is_numeric($sessionid))
    {   
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        ($sessionid == '' ? $response->addMessage("Session ID cannot be blank") : false);
        (!is_numeric($sessionid) ? $response->addMessage("Session ID must be numeric") : false);
        $response->send();
        exit;
        
    }
    
    if (!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1)
    {
        $response = new Response();
        $response->returnResponseError(401, "Access token is missing from the header or not long enough");
    }
    
    $accesstoken = $_SERVER['HTTP_AUTHORIZATION'];
    
    if ($_SERVER['REQUEST_METHOD'] === 'DELETE')
    {   
        try
        {
            $query = $writeDB->prepare('delete from tblsessions where id = :sessionid and accesstoken = :accesstoken');
            $query->bindParam(':sessionid', $sessionid, PDO::PARAM_INT);
            $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
            $query->execute();
            
            $rowCount = $query->rowCount();
            
            if ($rowCount === 0)
            {
                $response = new Response();
                $response->returnResponseError(400, "Failed to log out of this sessions using access token provided");
            }

            $returnData = [];
            $returnData['session_id'] = intval($sessionid);

            $response = new Response();
            $response->returnResponseSuccess(200, $returnData);

        }
        catch (PDOException $ex)
        {
            $response = new Response();
            $response->returnResponseError(500, "There was an issue logging out - please try again");
        }
    }
    elseif ($_SERVER['REQUEST_METHOD'] === 'PATCH')
    {
        if ($_SERVER['CONTENT_TYPE'] !== 'application/json')
        {
            $response = new Response();
            $response->returnResponseError(400, "Content type header not set to JSON");
        }

        $rawPatchData = file_get_contents('php://input');

        if (!$jsonData = json_decode($rawPatchData))
        {
            $response = new Response();
            $response->returnResponseError(400, "Request body is not valid JSON");
        }
        
        if (!isset($jsonData->refresh_token) || strlen($jsonData->refresh_token) < 1)
        {
            $response = new Response();
            $response->returnResponseError(400, "Refresh token not supplied or blank");
        }
        
        try
        {
                $refreshtoken = $jsonData->refresh_token;

                $query = $writeDB->prepare('SELECT tblsessions.id AS sessionid, 
                                            tblsessions.userid AS userid, 
                                            accesstoken, refreshtoken, 
                                            useractive, loginattempts, 
                                            accesstokenexpiry, 
                                            refreshtokenexpiry
                                            FROM 
                                            tblsessions, 
                                            tblusers 
                                            WHERE tblusers.id = tblsessions.userid 
                                            AND tblsessions.id = :sessionid 
                                            AND tblsessions.accesstoken = :accesstoken 
                                            AND tblsessions.refreshtoken = :refreshtoken');
                $query->bindParam(':sessionid', $sessionid, PDO::PARAM_INT);
                $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
                $query->bindParam(':refreshtoken', $refreshtoken, PDO::PARAM_STR);
                $query->execute(); 

                $rowCount = $query->rowCount();

                if ($rowCount === 0)
                {
                    $response = new Response();
                    $response->returnResponseError(401, "Accesstoken or refreshtoken is incorrect for session id");
                }

                $row = $query->fetch(PDO::FETCH_ASSOC);

                $returned_sessionid = $row['sessionid'];
                $returned_userid = $row['userid'];
                $returned_accesstoken = $row['accesstoken'];
                $returned_refreshtoken = $row['refreshtoken'];
                $returned_useractive = $row['useractive'];
                $returned_loginattempts = $row['loginattempts'];
                $returned_accesstokenexpiry = $row['accesstokenexpiry'];
                $returned_refreshtokenexpiry = $row['refreshtokenexpiry'];

                if ($returned_useractive !=='Y') 
                {
                    $response = new Response();
                    $response->returnResponseError(401, "User account is not active");
                }

                if ($returned_loginattempts >= 3) 
                {
                    $response = new Response();
                    $response->returnResponseError(401, "User account is currently locked out");
                }

                if (strtotime($returned_refreshtokenexpiry) < time()) 
                {
                    $response = new Response();
                    $response->returnResponseError(401, "Refreshtoken has expired - please log in again");
                }

                $accesstoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24).time()));
                $refreshtoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24).time()));

                $access_token_expiry_seconds = 1200;
                $refresh_token_expiry_seconds = 1209600;

                $query = $writeDB->prepare('UPDATE tblsessions SET accesstoken = :accesstoken, 
                                            accesstokenexpiry = date_add(NOW(), 
                                            INTERVAL :accesstokenexpiryseconds SECOND), 
                                            refreshtoken = :refreshtoken, 
                                            refreshtokenexpiry = date_add(NOW(), 
                                            INTERVAL :refreshtokenexpiryseconds SECOND) 
                                            WHERE id = :sessionid 
                                            AND userid = :userid 
                                            AND accesstoken = :returnedaccesstoken 
                                            AND refreshtoken = :returnedrefreshtoken');
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->bindParam(':sessionid', $returned_sessionid, PDO::PARAM_INT);
                $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
                $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);
                $query->bindParam(':refreshtoken', $refreshtoken, PDO::PARAM_STR);
                $query->bindParam(':refreshtokenexpiryseconds', $refresh_token_expiry_seconds, PDO::PARAM_INT);
                $query->bindParam(':returnedaccesstoken', $returned_accesstoken, PDO::PARAM_STR);
                $query->bindParam(':returnedrefreshtoken', $returned_refreshtoken, PDO::PARAM_STR);
                $query->execute();

                $rowCount = $query->rowCount();

                if ($rowCount === 0)
                {
                    $response = new Response();
                    $response->returnResponseError(401, "Accesstoken could not be refreshed - please log in again");
                }

                $returnData = [];
                $returnData['session_id'] = $returned_sessionid;
                $returnData['accesstoken'] = $accesstoken;
                $returnData['access_token_expiry'] = $access_token_expiry_seconds;
                $returnData['refreshtoken'] = $refreshtoken;
                $returnData['refresh_token_expiry'] = $refresh_token_expiry_seconds;

                $response = new Response();
                $response->returnResponseSuccess(200, $returnData);
        }
        catch (PDOException $ex)
        {
            error_log("Database query erro - ".$ex, 0);
            $response = new Response();
            $response->returnResponseError(500, "There was an issue refreshing access token - please log in again 199");
        }
    }
    else
    {
        $response = new Response();
        $response->returnResponseError(405, "Request method not allowed");
    }
}
elseif (empty($_GET))
{
    if ($_SERVER['REQUEST_METHOD'] !== "POST")
    {
        $response = new Response();
        $response->returnResponseError(405, "Request method not allowed 27");
    }

    // brute force delayment
    sleep(1);

    if ($_SERVER['CONTENT_TYPE'] !== 'application/json')
    {
        $response = new Response();
        $response->returnResponseError(400, "Content type header not set to JSON 36");
    }

    $rawPostData = file_get_contents('php://input');

    if (!$jsonData = json_decode($rawPostData))
    {
        $response = new Response();
        $response->returnResponseError(400, "Request body is not valid JSON 44");
    }
    
    if (!isset($jsonData->username) || !isset($jsonData->password))
    {
        $response = new Response();
        $response->returnResponseError(400, "Invalid credentials 50");
    }
    
    if (strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255)
    {
        $response = new Response();
        $response->returnResponseError(400, "Check the length of your credentials 56");
    }
    
    try
    {
        $username = $jsonData->username;
        $password = $jsonData->password;

        $query = $writeDB->prepare('select id, fullname, username, password, useractive, loginattempts from tblusers where username = :username');
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->execute();
        
        $rowCount = $query->rowCount();
        
        if ($rowCount === 0)
        {
            $response = new Response();
            $response->returnResponseError(401, "Credentials are incorrect 73");
        }
        
        $row = $query->fetch(PDO::FETCH_ASSOC);
        
        $returned_id = $row['id'];
        $returned_fullname = $row['fullname'];
        $returned_username = $row['username'];
        $returned_password = $row['password'];
        $returned_useractive = $row['useractive'];
        $returned_loginattempts = $row['loginattempts'];
        
        if ($returned_useractive !== "Y")
        {
            $response = new Response();
            $response->returnResponseError(401, "User account not active");
        }
        
        if ($returned_loginattempts >= 3)
        {
            $response = new Response();
            $response->returnResponseError(401, "User account is currently locked out");
        }

        if (!password_verify($password, $returned_password))
        {
            $query = $writeDB->prepare('update tblusers set loginattempts = loginattempts+1 where id = :id');
            $query->bindParam(':id', $returned_id, PDO::PARAM_INT);
            $query->execute();
            $response = new Response();
            $response->returnResponseError(401, "Credentials are incorrect");
        }

        // create accesstoken
        $accesstoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24))).time();
        $refreshtoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24))).time();
            
        $access_token_expiry_seconds = 1200;
        $refresh_token_expiry_seconds = 1209600;
        
    }
    catch(PDOException $ex)
    {
        $response = new Response();
        $response->returnResponseError(500, "Issue with logging in");
    }

    try
    {
        $writeDB->beginTransaction();

        $query = $writeDB->prepare('update tblusers set loginattempts = 0 where id = :id');
        $query->bindParam(':id', $returned_id, PDO::PARAM_INT);
        $query->execute();

        $query = $writeDB->prepare('insert into tblsessions (
                                    userid, 
                                    accesstoken, 
                                    accesstokenexpiry, 
                                    refreshtoken, 
                                    refreshtokenexpiry
                                    ) values (
                                    :userid, 
                                    :accesstoken, 
                                    date_add(NOW(), INTERVAL :accesstokenexpiryseconds SECOND), 
                                    :refreshtoken, 
                                    date_add(NOW(), INTERVAL :refreshtokenexpiryseconds SECOND))');

        $query->bindParam(':userid', $returned_id, PDO::PARAM_INT);
        $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
        $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);
        $query->bindParam(':refreshtoken', $refreshtoken, PDO::PARAM_STR);
        $query->bindParam(':refreshtokenexpiryseconds', $refresh_token_expiry_seconds, PDO::PARAM_INT);
        $query->execute();

        $lastsessionID = $writeDB->lastInsertId();

        $writeDB->commit();

        $returnData = [];
        $returnData['session_id'] = intval($lastsessionID);
        $returnData['access_token'] = $accesstoken;
        $returnData['access_token_expires_in'] = $access_token_expiry_seconds;
        $returnData['refresh_token'] = $refreshtoken;
        $returnData['refresh_token_expires_in'] = $refresh_token_expiry_seconds;
        
        $response = new Response();
        $response->returnResponseSuccess(201, $returnData);

    }
    catch (PDOException $ex)
    {   
        $writeDB->rollBack();
        $response = new Response();
        $response->returnResponseError(500, "There was an issue loggin in - please try again 163");
    }
}
else{

    $response = new Response();
    $response->returnResponseError(404, "Endpoint not found");
}
