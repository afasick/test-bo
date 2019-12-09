<?php
 /*********************************************************************************
 *          Filename: MyInfo.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "MyInfo.php";



check_security(1);

$sFormErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Form":
    Form_action($sAction);
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
<? Form_Show() ?>
    
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



function Form_action($sAction)
{
  global $db;
  global $sForm;
  global $sFormErr;
  
  $sParams = "";
  $sActionFileName = "ShoppingCart.php";

  

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKmember_id = get_param("PK_member_id");
    
    $sWhere .= "member_id=" . tosql($pPKmember_id, "Number");
    
  }
  
  $fldUserID = get_session("UserID");
  $fldmember_password = get_param("member_password");
  $fldname = get_param("name");
  $fldlast_name = get_param("last_name");
  $fldemail = get_param("email");
  $fldaddress = get_param("address");
  $fldphone = get_param("phone");
  $fldnotes = get_param("notes");
  $fldcard_type_id = get_param("card_type_id");
  $fldcard_number = get_param("card_number");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldmember_password))
      $sFormErr .= "The value in field Password* is required.<br>";
    
    if(!strlen($fldname))
      $sFormErr .= "The value in field First Name* is required.<br>";
    
    if(!strlen($fldlast_name))
      $sFormErr .= "The value in field Last Name* is required.<br>";
    
    if(!strlen($fldemail))
      $sFormErr .= "The value in field Email* is required.<br>";
    
    if(!is_number($fldcard_type_id))
      $sFormErr .= "The value in field Credit Card Type is incorrect.<br>";
    

    if(strlen($sFormErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "update":
      
        $sSQL = "update members set " .
          "member_password=" . tosql($fldmember_password, "Text") .
          ",first_name=" . tosql($fldname, "Text") .
          ",last_name=" . tosql($fldlast_name, "Text") .
          ",email=" . tosql($fldemail, "Text") .
          ",address=" . tosql($fldaddress, "Text") .
          ",phone=" . tosql($fldphone, "Text") .
          ",notes=" . tosql($fldnotes, "Text") .
          ",card_type_id=" . tosql($fldcard_type_id, "Number") .
          ",card_number=" . tosql($fldcard_number, "Text");
        $sSQL .= " where " . $sWhere;
    break;
  
  }

  if(strlen($sFormErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName);
  
}



function Form_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sFormErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldmember_id = "";
  $fldmember_login = "";
  $fldmember_password = "";
  $fldname = "";
  $fldlast_name = "";
  $fldemail = "";
  $fldaddress = "";
  $fldphone = "";
  $fldnotes = "";
  $fldcard_type_id = "";
  $fldcard_number = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Form">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">MyInfo</font></td></tr>
   <? if ($sFormErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sFormErr ?></font></td></tr><? } ?>
<? 

  if($sFormErr == "")
  {
    //-- Get primary key and form parameters
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldmember_id = strip(get_param("member_id"));
    $fldmember_password = strip(get_param("member_password"));
    $fldname = strip(get_param("name"));
    $fldlast_name = strip(get_param("last_name"));
    $fldemail = strip(get_param("email"));
    $fldaddress = strip(get_param("address"));
    $fldphone = strip(get_param("phone"));
    $fldnotes = strip(get_param("notes"));
    $fldcard_type_id = strip(get_param("card_type_id"));
    $fldcard_number = strip(get_param("card_number"));
  }

  
  $pmember_id = get_session("UserID");
  if( !strlen($pmember_id)) $bPK = false;
  
  $sWhere .= "member_id=" . tosql($pmember_id, "Number");
  $PK_member_id = $pmember_id;

  $sSQL = "select * from members where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Form"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldmember_id = $db->f("member_id");
    $fldmember_login = $db->f("member_login");
    if($sFormErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldmember_password = $db->f("member_password");
      $fldname = $db->f("first_name");
      $fldlast_name = $db->f("last_name");
      $fldemail = $db->f("email");
      $fldaddress = $db->f("address");
      $fldphone = $db->f("phone");
      $fldnotes = $db->f("notes");
      $fldcard_type_id = $db->f("card_type_id");
      $fldcard_number = $db->f("card_number");
    }
  }

  else
  {
    if($sFormErr == "")
    {
      $fldmember_id = tohtml(get_session("UserID"));
    }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Login</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldmember_login)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Password*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="password" name="member_password" maxlength="20" value="<?= tohtml($fldmember_password) ?>" size="20" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">First Name*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="name" maxlength="50" value="<?= tohtml($fldname) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Last Name*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="last_name" maxlength="50" value="<?= tohtml($fldlast_name) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Email*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="email" maxlength="50" value="<?= tohtml($fldemail) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Address</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="address" maxlength="50" value="<?= tohtml($fldaddress) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Phone</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="phone" maxlength="50" value="<?= tohtml($fldphone) ?>" size="50" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Notes</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
  <textarea name="notes" cols="50" rows="5"><?= tohtml($fldnotes) ?></textarea></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Credit Card Type</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><select name="card_type_id"><?= get_options("select card_type_id, name from card_types order by 2",false,false,$fldcard_type_id);?></select></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Credit Card Number</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="card_number" maxlength="50" value="<?= tohtml($fldcard_number) ?>" size="50" ></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Form"))) { ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Update" onclick="document.Form.FormAction.value = 'update';">
   
 <? } ?>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.Form.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="Form">
  
  <input type="hidden" name="PK_member_id" value="<?= $pmember_id ?>">  
  <input type="hidden" name="member_id" value="<?= tohtml($fldmember_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>