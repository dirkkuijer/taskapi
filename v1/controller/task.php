<?php

require_once('db.php');
require_once('../model/Task.php');
require_once('../model/Response.php');

try
{
    $writeDB = DB::connectionWriteDB();
    $readDB = DB::connectionReadDB();

}
catch (PDOException $ex)
{   
    error_log("Connection error - ".$ex, 0);
    $response = new Response();
    $response->returnResponseError(500, "No DB connection");
}

    
    if (!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1)
    {
        $response = new Response();
        $response->returnResponseError(401, "Access token is missing or blank");
    }

    try 
    {

        $accesstoken = $_SERVER['HTTP_AUTHORIZATION'];
        
        $query = $writeDB->prepare('SELECT userid, 
                                    accesstokenexpiry, 
                                    useractive, 
                                    loginattempts 
                                    FROM tblsessions, tblusers 
                                    WHERE tblsessions.userid = tblusers.id 
                                    AND accesstoken = :accesstoken');
        $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();
        

        if ($rowCount === 0)
        {
            $response = new Response();
            $response->returnResponseError(401, "Invalid access token");
        }
        
        $row = $query->fetch(PDO::FETCH_ASSOC);
        
        $returned_userid = $row['userid'];
        $returned_accesstokenexpiry = $row['accesstokenexpiry'];
        $returned_useractive = $row['useractive'];
        $returned_loginattempts = $row['loginattempts'];
        
        if ($returned_useractive !== 'Y' )
        {
            $response = new Response();
            $response->returnResponseError(401, "User account not active");
        }
        
        if ($returned_loginattempts >= 3 )
        {
            $response = new Response();
            $response->returnResponseError(401, "User account currently locked out");
        }
        
        if (strtotime($returned_accesstokenexpiry) < time())
        {
            $response = new Response();
            $response->returnResponseError(401, "Acces token expired");
        }
        
    }
    catch (PDOException $ex)
    {
        $response = new Response();
        $response->returnResponseError(500, "There was an authentication error - please try again");
    }
    // end auth script
if (array_key_exists("taskid",$_GET)) {
    // get task id from query string
    $taskid = $_GET['taskid'];
    
    //check to see if task id in query string is not empty and is number, if not return json error
    if($taskid == '' || !is_numeric($taskid)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Task ID cannot be blank or must be numeric");
        $response->send();
        exit;
    }
    // handle options request method for CORS
if ($_SERVER['REQUEST_METHOD'] === "OPTIONS")
{
    header('Access-Control-Allow-Methods: POST, GET, DELETE OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Max-Age: 86400');
    $response = new Response();
    $response->returnResponseSuccess(200, []);
}
    if ($_SERVER['REQUEST_METHOD'] === 'GET')
    {
        try
        {
            $query = $readDB->prepare('SELECT id, 
                                            title, 
                                            description, 
                                            DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") AS deadline, 
                                            completed 
                                            FROM tbltasks 
                                            WHERE id = :taskid 
                                            AND userid = :userid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();
            
            $rowCount = $query->rowCount();
            
            $taskArray = [];
            
            if ($rowCount === 0) 
            {
                $response = new Response();
                $response->returnResponseError(404, "Task not found");
            }
            
            while ($row = $query->fetch(PDO::FETCH_ASSOC))
            {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $tasksArray[] = $task->returnTaskAsArray();
            }
            
            $returnData = [];
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $tasksArray;

            $response = new Response();
            $response->returnResponseSuccess(200, $returnData);
        }
        catch (TaskException $ex)
        {
            $response = new Response();
            $response->returnResponseError(500, false, $ex->getMessage());
            
        }
        catch (PDOException $ex)
        {
            error_log("DataBase query error - ".$ex, 0);
            $response = new Response();
            $response->returnResponseError(500, "Failed to get Task");
        }
    }
    elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE')
    {
        try
        {
            $query = $writeDB->prepare('DELETE FROM tbltasks WHERE id = :taskid AND userid = :userid');
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            if ($rowCount === 0)
            {
                $response = new Response();
                $response->returnResponseError(404, "Task not found");
            }
            
                $response = new Response();
                $response->returnResponseError(200, "Task was deleted");
            }
            catch (PDOException $ex)
            {
                $response = new Response();
                $response->returnResponseError(500, "Failed to delete the task");
            }
        }
        elseif ($_SERVER['REQUEST_METHOD'] === 'PATCH')
        {
            try {
                // check request's content type header is JSON
                if($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                    // set up response for unsuccessful request
                    $response = new Response();
                    $response->returnResponseError(400, "Content Type header not set to JSON");
                }
                
                // get PATCH request body as the PATCHed data will be JSON format
                $rawPatchData = file_get_contents('php://input');
                
                if(!$jsonData = json_decode($rawPatchData)) {
                    // set up response for unsuccessful request
                    $response = new Response();
                    $response->returnResponseError(400, "Request body is not valid JSON");
                }
                
                // set task field updated to false initially
                $title_updated = false;
                $description_updated = false;
                $deadline_updated = false;
                $completed_updated = false;
                
                // create blank query fields string to append each field to
                $queryFields = "";
                
                // check if title exists in PATCH
                if(isset($jsonData->title)) {
                    // set title field updated to true
                    $title_updated = true;
                    // add title field to query field string
                    $queryFields .= "title = :title, ";
                }
                
                // check if description exists in PATCH
                if(isset($jsonData->description)) {
                    // set description field updated to true
                    $description_updated = true;
                    // add description field to query field string
                    $queryFields .= "description = :description, ";
                }
                
                // check if deadline exists in PATCH
                if(isset($jsonData->deadline)) {
                    // set deadline field updated to true
                    $deadline_updated = true;
                    // add deadline field to query field string
                    $queryFields .= "deadline = STR_TO_DATE(:deadline, '%d/%m/%Y %H:%i'), ";
                }
                
                // check if completed exists in PATCH
                if(isset($jsonData->completed)) {
                    // set completed field updated to true
                    $completed_updated = true;
                    // add completed field to query field string
                    $queryFields .= "completed = :completed, ";
                }
                
                // remove the right hand comma and trailing space
                $queryFields = rtrim($queryFields, ", ");
                
                // check if any task fields supplied in JSON
                if($title_updated === false && $description_updated === false && $deadline_updated === false && $completed_updated === false) {
                    $response = new Response();
                    $response->returnResponseError(400, "No task fields provided");
                }
                
                // create db query to get task from database to update - use master db
                $query = $writeDB->prepare('SELECT id, 
                                            title, 
                                            description, 
                                            DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") AS deadline, 
                                            completed 
                                            FROM tbltasks 
                                            WHERE id = :taskid
                                            AND userid = :userid');
                $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();
            
                // get row count
                $rowCount = $query->rowCount();
            
                // make sure that the task exists for a given task id
                if($rowCount === 0) {
                    // set up response for unsuccessful return
                    $response = new Response();
                    $response->returnResponseError(404, "No task found to update");
                }
                
                // for each row returned - should be just one
                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    // create new task object
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                }
                
                // create the query string including any query fields
                $queryString = "update tbltasks set ".$queryFields." where id = :taskid";
                // prepare the query
                $query = $writeDB->prepare($queryString);
                
                // if title has been provided
                if($title_updated === true) {
                    // set task object title to given value (checks for valid input)
                    $task->setTitle($jsonData->title);
                    // get the value back as the object could be handling the return of the value differently to
                    // what was provided
                    $up_title = $task->getTitle();
                    // bind the parameter of the new value from the object to the query (prevents SQL injection)
                    $query->bindParam(':title', $up_title, PDO::PARAM_STR);
                }
                
                // if description has been provided
                if($description_updated === true) {
                    // set task object description to given value (checks for valid input)
                    $task->setDescription($jsonData->description);
                    // get the value back as the object could be handling the return of the value differently to
                    // what was provided
                    $up_description = $task->getDescription();
                    // bind the parameter of the new value from the object to the query (prevents SQL injection)
                    $query->bindParam(':description', $up_description, PDO::PARAM_STR);
                }
                
                // if deadline has been provided
                if($deadline_updated === true) {
                    // set task object deadline to given value (checks for valid input)
                    $task->setDeadline($jsonData->deadline);
                    // get the value back as the object could be handling the return of the value differently to
                    // what was provided
                    $up_deadline = $task->getDeadline();
                    // bind the parameter of the new value from the object to the query (prevents SQL injection)
                    $query->bindParam(':deadline', $up_deadline, PDO::PARAM_STR);
                }
                
                // if completed has been provided
                if($completed_updated === true) {
                    // set task object completed to given value (checks for valid input)
                    $task->setCompleted($jsonData->completed);
                    // get the value back as the object could be handling the return of the value differently to
                    // what was provided
                    $up_completed= $task->getCompleted();
                    // bind the parameter of the new value from the object to the query (prevents SQL injection)
                    $query->bindParam(':completed', $up_completed, PDO::PARAM_STR);
                }
                
                // bind the task id provided in the query string
                $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
                // run the query
                    $query->execute();
                
                // get affected row count
                $rowCount = $query->rowCount();
            
                // check if row was actually updated, could be that the given values are the same as the stored values
                if($rowCount === 0) {
                    // set up response for unsuccessful return
                    $response = new Response();
                    $response->returnResponseError(400, "Task not updated - given values may be the same as the stored values");
                }
                
                // create db query to return the newly edited task - connect to master database
                $query = $writeDB->prepare('SELECT id, 
                                                title, 
                                                description, 
                                                DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") AS deadline, 
                                                completed 
                                                FROM tbltasks 
                                                WHERE id = :taskid
                                                AND userid = :userid');
                $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
                $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
                $query->execute();
            
                // get row count
                $rowCount = $query->rowCount();
            
                // check if task was found
                if($rowCount === 0) {
                    // set up response for unsuccessful return
                    $response = new Response();
                    $response->returnResponseError(404, "No task found");
                }
                // create task array to store returned tasks
                $taskArray = [];
            
                // for each row returned
                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    // create new task object for each row returned
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
            
                    // create task and store in array for return in json data
                    $taskArray[] = $task->returnTaskAsArray();
                }
                // bundle tasks and rows returned into an array to return in the json data
                $returnData = [];
                $returnData['rows_returned'] = $rowCount;
                $returnData['tasks'] = $taskArray;
            
                // set up response for successful return
                $response = new Response();
                $response->returnResponseSuccess(200, $returnData);
            }
        catch (TaskException $ex)
        {
            $response = new Response();
            $response->returnResponseError(400, $ex->getMessage());
        }
        catch (PDOException $ex)
        {   
            error_log("Database query error - ".$ex, 0);
            $response = new Response();
            $response->returnResponseError(500, "Failed to insert task into database - check submitted data for errors");
        }
    }
    else 
    {
        $response = new Response();
        $response->returnResponseError(405, "Request not allowed");
    }
}
elseif (array_key_exists("completed", $_GET))
{
    $completed = $_GET['completed'];
    
    if ($completed !== "Y" && $completed !== "N")
    {
        $response = new Response();
        $response->returnResponseError(400, "Completed filter must be Y or N");
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'GET')
    {
        try
        {
            $query = $readDB->prepare('SELECT id, 
                                            title, 
                                            description, 
                                            DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") AS deadline, 
                                            completed 
                                            FROM tbltasks 
                                            WHERE completed = :completed
                                            AND userid = :userid');
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_STR);
            $query->execute();

            $rowCount = $query->rowCount();

            $taskArray = [];

            while ($row = $query->fetch(PDO::FETCH_ASSOC))
            {   
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            
            $returnData = [];
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->returnResponseSuccess(200, $returnData);
        }
        catch (TaskException $ex)
        {
            $response = new Response();
            $response->returnResponseError(500, $ex->getMessage());
        }
        catch (PDOException $ex) 
        {
            error_log("Database query error -" .$ex, 0);
            $response = new Response();
            $response->returnResponseError(500, $ex->getMessage());
        }
    }
    else 
    {
        $response = new Response();
        $response->returnResponseError(405, "Request not allowed");
    }
}
elseif (array_key_exists("page", $_GET))
{
    if ($_SERVER['REQUEST_METHOD'] === 'GET')
    {
        $page = $_GET['page'];

        if ($page == '' || !is_numeric($page))
        {
            $response = new Response();
            $response->returnResponseError(400, "Page number cannot be blank and must be nummeric");
        }
        
        $limitPerPage = 20;
        
        try
        {
            $query = $readDB->prepare('SELECT count(id) AS totalNoOfTasks FROM tbltasks WHERE userid = :userid');
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $row = $query->fetch(PDO::FETCH_ASSOC);
            $tasksCount = intval($row['totalNoOfTasks']);

            $numOfPages = ceil($tasksCount/$limitPerPage);

            if ($numOfPages == 0)
            {
                $numOfPages = 1;
            }

            if ($page > $numOfPages || $page == 0)
            {
                $response = new Response();
                $response->returnResponseError(404, "Page not found");
            }

            $offset = ($page = 1 ? 0 : ($limitPerPage * ($page-1)));

            $query = $readDB->prepare('SELECT id, 
                                        title, description, 
                                        DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") AS deadline, 
                                        completed 
                                        FROM tbltasks 
                                        WHERE userid = :userid
                                        LIMIT :pglimit offset :offset');
            $query-> bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query-> bindParam(':pglimit', $limitPerPage, PDO::PARAM_INT);
            $query-> bindParam(':offset', $offset, PDO::PARAM_INT);
            $query->execute();
            
            $rowCount = $query->rowCount();
            
            $taskArray = [];

            while ($row = $query->fetch(PDO::FETCH_ASSOC))
            {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();

            }

            $returnData = [];
            $returnData['rows_returned'] = $rowCount;
            $returnData['total_rows'] = $tasksCount;
            $returnData['total_pages'] = $numOfPages;
            ($page < $numOfPages ? $returnData['has_next_page'] = true : $returnData['has_next_page'] = false);
            ($page < $numOfPages ? $returnData['has_previous_page'] = true : $returnData['has_previous_page'] = false);
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->returnResponseSuccess(200, $returnData);
        
        }
        catch(TaskException $ex)
        {
            $response = new Response();
            $response->returnResponseError(500, $ex->getMessage());
        }
        catch(PDOException $ex)
        {
            error_log("Database query error -" .$ex, 0);
            $response = new Response();
            $response->returnResponseError(500, "Failed to get tasks");
        }
    }
    else 
    {
        $response = new Response();
        $response->returnResponseError(405, "Request is not allowed");
    }
}
elseif (empty($_GET))
{
    if ($_SERVER['REQUEST_METHOD'] === 'GET')
    {
        try
        {
            $query = $readDB->prepare('SELECT id, 
                                            title, 
                                            description, 
                                            DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") AS deadline, 
                                            completed 
                                            FROM tbltasks
                                            WHERE 
                                            userid = :userid');
            $query-> bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();
            $taskArray = [];

            while ($row = $query->fetch(PDO::FETCH_ASSOC))
            {
                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
            $returnData = [];
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->returnResponseSuccess(200, $returnData);

        }
        catch (TaskException$ex)
        {
            $response = new Response();
            $response->returnResponseError(500, $ex->getMessage());
        }
        catch (PDOException $ex)
        {
            error_log("Database query error - ".$ex, 0);
            $response = new Response();
            $response->returnResponseError(500, "Failed to get tasks");
        {

        }
    }
}
elseif($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // create task
    try {
      // check request's content type header is JSON
      if($_SERVER['CONTENT_TYPE'] !== 'application/json') {
        // set up response for unsuccessful request
        $response = new Response();
        $response->returnResponseError(400, "Content Type header not set to JSON");
      }
      
      // get POST request body as the POSTed data will be JSON format
      $rawPostData = file_get_contents('php://input');
      
      if(!$jsonData = json_decode($rawPostData)) {
        // set up response for unsuccessful request
        $response = new Response();
        $response->returnResponseError(400, "Request body is not valid JSON");
      }
      
      // check if post request contains title and completed data in body as these are mandatory
      if(!isset($jsonData->title) || !isset($jsonData->completed)) {
        $response = new Response();
        $message = (!isset($jsonData->title) ? $response->addMessage("Title field is mandatory and must be provided") : null);
        $message = (!isset($jsonData->completed) ? $response->addMessage("Completed field is mandatory and must be provided") : false);
        $response->returnResponseError(400, $message);
      }
      
      // create new task with data, if non mandatory fields not provided then set to null
      $newTask = new Task(null, $jsonData->title, (isset($jsonData->description) ? $jsonData->description : null), (isset($jsonData->deadline) ? $jsonData->deadline : null), $jsonData->completed);
      // get title, description, deadline, completed and store them in variables
      $title = $newTask->getTitle();
      $description = $newTask->getDescription();
      $deadline = $newTask->getDeadline();
      $completed = $newTask->getCompleted();

      // create db query
      $query = $writeDB->prepare('INSERT INTO tbltasks 
                                    (
                                        title, 
                                        description, 
                                        deadline, 
                                        completed, 
                                        userid
                                    ) 
                                        values 
                                    (
                                        :title, 
                                        :description, STR_TO_DATE(:deadline, \'%d/%m/%Y %H:%i\'),
                                        :completed, 
                                        :userid
                                    )
                                ');
      $query->bindParam(':title', $title, PDO::PARAM_STR);
      $query->bindParam(':description', $description, PDO::PARAM_STR);
      $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
      $query->bindParam(':completed', $completed, PDO::PARAM_STR);
      $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
      $query->execute();
      
      // get row count
      $rowCount = $query->rowCount();

      // check if row was actually inserted, PDO exception should have caught it if not.
      if($rowCount === 0) {
        // set up response for unsuccessful return
        $response = new Response();
        $response->returnResponseError(500, "Failed to create task");
      }
      
      // get last task id so we can return the Task in the json
      $lastTaskID = $writeDB->lastInsertId();
      // create db query to get newly created task - get from master db not read slave as replication may be too slow for successful read
      $query = $writeDB->prepare('SELECT 
                                    id, 
                                    title, 
                                    description, 
                                    DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") AS deadline, 
                                    completed
                                    FROM 
                                    tbltasks 
                                    WHERE id = :taskid
                                    AND userid = :userid');
      $query->bindParam(':taskid', $lastTaskID, PDO::PARAM_INT);
      $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
      $query->execute();

      // get row count
      $rowCount = $query->rowCount();
      
      // make sure that the new task was returned
      if($rowCount === 0) {
        // set up response for unsuccessful return
        $response = new Response();
        $response->returnResponseError(500, "Failed to retrieve task after creation");
      }
      
      // create empty array to store tasks
      $taskArray = [];

      // for each row returned - should be just one
      while($row = $query->fetch(PDO::FETCH_ASSOC)) {
        // create new task object
        $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);

        // create task and store in array for return in json data
        $taskArray[] = $task->returnTaskAsArray();
      }
      // bundle tasks and rows returned into an array to return in the json data
      $returnData = [];
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $taskArray;

      //set up response for successful return
      $response = new Response();
      $response->returnResponseSuccess(201, $returnData);
      exit;      
    }
    // if task fails to create due to data types, missing fields or invalid data then send error json
    catch(TaskException $ex) {
      $response = new Response();
      $response->returnResponseError(400, $ex->getMessage());
    }
    // if error with sql query return a json error
    catch(PDOException $ex) {
      error_log("Database Query Error: ".$ex, 0);
      $response = new Response();
      $response->returnResponseError(500, "Failed to update task - check your data for errors");
    }
  }
  // if any other request method apart from GET or POST is used then return 405 method not allowed
  else {
    $response = new Response();
    $response->returnResponseError(405, "Request method not allowed");
  } 
}
// return 404 error if endpoint not available
else {
  $response = new Response();
  $response->returnResponseError(404, "Endpoint not found");
}
?>