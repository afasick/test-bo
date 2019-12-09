<?php
 /*********************************************************************************
 *          Filename: CardTypesRecord.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "CardTypesRecord.php";



check_security(2);

$sCardTypesErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "CardTypes":
    CardTypes_action($sAction);
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
<? CardTypes_Show() ?>
    
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



function CardTypes_action($sAction)
{
  global $db;
  global $sForm;
  global $sCardTypesErr;
  
  $sParams = "";
  $sActionFileName = "CardTypesGrid.php";

  

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKcard_type_id = get_param("PK_card_type_id");
    
    $sWhere .= "card_type_id=" . tosql($pPKcard_type_id, "Number");
    
  }
  
  $fldname = get_param("name");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldname))
      $sCardTypesErr .= "The value in field Name is required.<br>";
    

    if(strlen($sCardTypesErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "insert":
      
        $sSQL = "insert into card_types (" . 
          "name)" . 
          " values (" . 
          tosql($fldname, "Text") . ")";
    break;
    case "update":
      
        $sSQL = "update card_types set " .
          "name=" . tosql($fldname, "Text");
        $sSQL .= " where " . $sWhere;
    break;
  
    case "delete":
      
        $sSQL = "delete from card_types where " . $sWhere;
    break;
  
  }

  if(strlen($sCardTypesErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName);
  
}



function CardTypes_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sCardTypesErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldcard_type_id = "";
  $fldname = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="CardTypes">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Card Type</font></td></tr>
   <? if ($sCardTypesErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sCardTypesErr ?></font></td></tr><? } ?>
<? 

  if($sCardTypesErr == "")
  {
    //-- Get primary key and form parameters
    $fldcard_type_id = get_param("card_type_id");
    $pcard_type_id = get_param("card_type_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldcard_type_id = strip(get_param("card_type_id"));
    $fldname = strip(get_param("name"));
    $pcard_type_id = get_param("PK_card_type_id");
  }

  
  if( !strlen($pcard_type_id)) $bPK = false;
  
  $sWhere .= "card_type_id=" . tosql($pcard_type_id, "Number");
  $PK_card_type_id = $pcard_type_id;

  $sSQL = "select * from card_types where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "CardTypes"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldcard_type_id = $db->f("card_type_id");
    if($sCardTypesErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldname = $db->f("name");
    }
  }

  else
  {
    if($sCardTypesErr == "")
    {
      $fldcard_type_id = tohtml(get_param("card_type_id"));
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
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="CardTypes"))) { ?>

<? if (!$bPK) { ?>
   <input type="submit" value="Insert" onclick="document.CardTypes.FormAction.value = 'insert';">
   <input type="hidden" value="insert" name="FormAction"/>
<? } ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Update" onclick="document.CardTypes.FormAction.value = 'update';">
   
 <? } ?>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Delete" onclick="document.CardTypes.FormAction.value = 'delete';">
   <? } ?>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.CardTypes.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="CardTypes">
  
  <input type="hidden" name="PK_card_type_id" value="<?= $pcard_type_id ?>">  
  <input type="hidden" name="card_type_id" value="<?= tohtml($fldcard_type_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>