<?php
 /*********************************************************************************
 *          Filename: CategoriesRecord.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "CategoriesRecord.php";



check_security(2);

$sCategoriesErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Categories":
    Categories_action($sAction);
  break;
}

?><html>
<head>
<title>Book Store</title>
<meta name="GENERATOR" content="YesSoftware CodeCharge v.1.1.19 using 'PHP.ccp'">
<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="expires" content="0"> 
<meta http-equiv="cache-control" content="no-cache">
</head>
<body style="background-color: #FFFFFF; color: #000000; font-family: Arial, Tahoma, Verdana, Helveticabackground-color: #FFFFFF; color: #000000; font-family: Arial, Tahoma, Verdana, Helvetica">
<center>
 <table>
  <tr>
   <td valign="top">
 <? Menu_Show() ?>
   
   </td>
  </tr>
 </table>
</center>
<hr>
 <table>
  <tr>
   
   <td valign="top">
<? Categories_Show() ?>
    
   </td>
  </tr>
 </table>

<center>
<hr size=1 width=60%>
 <table>
  <tr>
   <td valign="top">
<? Footer_Show() ?>
    </td>
   
  </tr>
 </table>
 
<center><font face="Arial"><small>This dynamic site was generated with <a href="http://www.codecharge.com">CodeCharge</a></small></font></center>
</body>
</html>
<? 



//********************************************************************************



function Categories_action($sAction)
{
  global $db;
  global $sForm;
  global $sCategoriesErr;
  
  $sParams = "";
  $sActionFileName = "CategoriesGrid.php";

  

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKcategory_id = get_param("PK_category_id");
    
    $sWhere .= "category_id=" . tosql($pPKcategory_id, "Number");
    
  }
  
  $fldname = get_param("name");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldname))
      $sCategoriesErr .= "The value in field Name is required.<br>";
    

    if(strlen($sCategoriesErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "insert":
      
        $sSQL = "insert into categories (" . 
          "name)" . 
          " values (" . 
          tosql($fldname, "Text") . ")";
    break;
    case "update":
      
        $sSQL = "update categories set " .
          "name=" . tosql($fldname, "Text");
        $sSQL .= " where " . $sWhere;
    break;
  
    case "delete":
      
        $sSQL = "delete from categories where " . $sWhere;
    break;
  
  }

  if(strlen($sCategoriesErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName);
  
}



function Categories_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sCategoriesErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldcategory_id = "";
  $fldname = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Categories">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Categories</font></td></tr>
   <? if ($sCategoriesErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sCategoriesErr ?></font></td></tr><? } ?>
<? 

  if($sCategoriesErr == "")
  {
    //-- Get primary key and form parameters
    $fldcategory_id = get_param("category_id");
    $pcategory_id = get_param("category_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldcategory_id = strip(get_param("category_id"));
    $fldname = strip(get_param("name"));
    $pcategory_id = get_param("PK_category_id");
  }

  
  if( !strlen($pcategory_id)) $bPK = false;
  
  $sWhere .= "category_id=" . tosql($pcategory_id, "Number");
  $PK_category_id = $pcategory_id;

  $sSQL = "select * from categories where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Categories"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldcategory_id = $db->f("category_id");
    if($sCategoriesErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldname = $db->f("name");
    }
  }

  else
  {
    if($sCategoriesErr == "")
    {
      $fldcategory_id = tohtml(get_param("category_id"));
    }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Name</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="name" maxlength="50" value="<?= tohtml($fldname) ?>" size="50" ></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Categories"))) { ?>

<? if (!$bPK) { ?>
   <input type="submit" value="Insert" onclick="document.Categories.FormAction.value = 'insert';">
   <input type="hidden" value="insert" name="FormAction"/>
<? } ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Update" onclick="document.Categories.FormAction.value = 'update';">
   
 <? } ?>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Delete" onclick="document.Categories.FormAction.value = 'delete';">
   <? } ?>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.Categories.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="Categories">
  
  <input type="hidden" name="PK_category_id" value="<?= $pcategory_id ?>">  
  <input type="hidden" name="category_id" value="<?= tohtml($fldcategory_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>