<?php
 /*********************************************************************************
 *          Filename: MembersRecord.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "MembersRecord.php";



check_security(2);

$sMembersErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Members":
    Members_action($sAction);
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
<? Members_Show() ?>
    <SCRIPT Language="JavaScript">
if (document.forms["Members"])
document.Members.onsubmit=delconf;
function delconf() {
if (document.Members.FormAction.value == 'delete')
  return confirm('Delete record?');
}
</SCRIPT>
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



function Members_action($sAction)
{
  global $db;
  global $sForm;
  global $sMembersErr;
  
  $sParams = "";
  $sActionFileName = "MembersGrid.php";

  
  $sParams = "?";
  $sParams .= "member_login=" . tourl(get_param("Trn_member_login"));

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName . $sParams); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKmember_id = get_param("PK_member_id");
    
    $sWhere .= "member_id=" . tosql($pPKmember_id, "Number");
    
  }
  
  $fldmember_login = get_param("member_login");
  $fldmember_password = get_param("member_password");
  $fldmember_level = get_param("member_level");
  $fldname = get_param("name");
  $fldlast_name = get_param("last_name");
  $fldemail = get_param("email");
  $fldphone = get_param("phone");
  $fldaddress = get_param("address");
  $fldnotes = get_param("notes");
  $fldcard_type_id = get_param("card_type_id");
  $fldcard_number = get_param("card_number");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldmember_login))
      $sMembersErr .= "The value in field Login* is required.<br>";
    
    if(!strlen($fldmember_password))
      $sMembersErr .= "The value in field Password* is required.<br>";
    
    if(!strlen($fldmember_level))
      $sMembersErr .= "The value in field Level* is required.<br>";
    
    if(!strlen($fldname))
      $sMembersErr .= "The value in field First Name* is required.<br>";
    
    if(!strlen($fldlast_name))
      $sMembersErr .= "The value in field Last Name* is required.<br>";
    
    if(!strlen($fldemail))
      $sMembersErr .= "The value in field Email* is required.<br>";
    
    if(!is_number($fldmember_level))
      $sMembersErr .= "The value in field Level* is incorrect.<br>";
    
    if(!is_number($fldcard_type_id))
      $sMembersErr .= "The value in field Credit Card Type is incorrect.<br>";
    
    if(strlen($fldmember_login) )
    {
      $iCount = 0;

      if($sAction == "insert")
        $iCount = dlookup("members", "count(*)", "member_login=" . tosql($fldmember_login, "Text"));
      else if($sAction == "update")
        $iCount = dlookup("members", "count(*)", "member_login=" . tosql($fldmember_login, "Text") . " and not(" . $sWhere . ")");
  
      if($iCount > 0)
        $sMembersErr .= "The value in field Login* is already in database.<br>";
    }                                                                               
    

    if(strlen($sMembersErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "insert":
      
        $sSQL = "insert into members (" . 
          "member_login," . 
          "member_password," . 
          "member_level," . 
          "first_name," . 
          "last_name," . 
          "email," . 
          "phone," . 
          "address," . 
          "notes," . 
          "card_type_id," . 
          "card_number)" . 
          " values (" . 
          tosql($fldmember_login, "Text") . "," .
          tosql($fldmember_password, "Text") . "," .
          tosql($fldmember_level, "Number") . "," .
          tosql($fldname, "Text") . "," .
          tosql($fldlast_name, "Text") . "," .
          tosql($fldemail, "Text") . "," .
          tosql($fldphone, "Text") . "," .
          tosql($fldaddress, "Text") . "," .
          tosql($fldnotes, "Text") . "," .
          tosql($fldcard_type_id, "Number") . "," .
          tosql($fldcard_number, "Text") . ")";
    break;
    case "update":
      
        $sSQL = "update members set " .
          "member_login=" . tosql($fldmember_login, "Text") .
          ",member_password=" . tosql($fldmember_password, "Text") .
          ",member_level=" . tosql($fldmember_level, "Number") .
          ",first_name=" . tosql($fldname, "Text") .
          ",last_name=" . tosql($fldlast_name, "Text") .
          ",email=" . tosql($fldemail, "Text") .
          ",phone=" . tosql($fldphone, "Text") .
          ",address=" . tosql($fldaddress, "Text") .
          ",notes=" . tosql($fldnotes, "Text") .
          ",card_type_id=" . tosql($fldcard_type_id, "Number") .
          ",card_number=" . tosql($fldcard_number, "Text");
        $sSQL .= " where " . $sWhere;
    break;
  
    case "delete":
      
        $sSQL = "delete from members where " . $sWhere;
    break;
  
  }

  if(strlen($sMembersErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName . $sParams);
  
}



function Members_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sMembersErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldmember_id = "";
  $fldmember_login = "";
  $fldmember_password = "";
  $fldmember_level = "";
  $fldname = "";
  $fldlast_name = "";
  $fldemail = "";
  $fldphone = "";
  $fldaddress = "";
  $fldnotes = "";
  $fldcard_type_id = "";
  $fldcard_number = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Members">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Members</font></td></tr>
   <? if ($sMembersErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sMembersErr ?></font></td></tr><? } ?>
<? 

  if($sMembersErr == "")
  {
    //-- Get primary key and form parameters
    $fldmember_login = get_param("member_login");
    $fldmember_id = get_param("member_id");
    $Trn_member_login = get_param("member_login");
    $pmember_id = get_param("member_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldmember_id = strip(get_param("member_id"));
    $fldmember_login = strip(get_param("member_login"));
    $fldmember_password = strip(get_param("member_password"));
    $fldmember_level = strip(get_param("member_level"));
    $fldname = strip(get_param("name"));
    $fldlast_name = strip(get_param("last_name"));
    $fldemail = strip(get_param("email"));
    $fldphone = strip(get_param("phone"));
    $fldaddress = strip(get_param("address"));
    $fldnotes = strip(get_param("notes"));
    $fldcard_type_id = strip(get_param("card_type_id"));
    $fldcard_number = strip(get_param("card_number"));
    $Trn_member_login = get_param("Trn_member_login");
    $pmember_id = get_param("PK_member_id");
  }

  
  if( !strlen($pmember_id)) $bPK = false;
  
  $sWhere .= "member_id=" . tosql($pmember_id, "Number");
  $PK_member_id = $pmember_id;

  $sSQL = "select * from members where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Members"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldmember_id = $db->f("member_id");
    if($sMembersErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldmember_login = $db->f("member_login");
      $fldmember_password = $db->f("member_password");
      $fldmember_level = $db->f("member_level");
      $fldname = $db->f("first_name");
      $fldlast_name = $db->f("last_name");
      $fldemail = $db->f("email");
      $fldphone = $db->f("phone");
      $fldaddress = $db->f("address");
      $fldnotes = $db->f("notes");
      $fldcard_type_id = $db->f("card_type_id");
      $fldcard_number = $db->f("card_number");
    }
  }

  else
  {
    if($sMembersErr == "")
    {
      $fldmember_id = tohtml(get_param("member_id"));
      $fldmember_login = tohtml(get_param("member_login"));
    }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Login*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="member_login" maxlength="20" value="<?= tohtml($fldmember_login) ?>" size="20" ></font>
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
         <font style="font-size: 10pt; color: #000000">Level*</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><select name="member_level"><?= get_lov_options('1;Member;2;Administrator',false,true,$fldmember_level);?></select></font>
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
         <font style="font-size: 10pt; color: #000000">Phone</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="phone" maxlength="50" value="<?= tohtml($fldphone) ?>" size="50" ></font>
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
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Members"))) { ?>

<? if (!$bPK) { ?>
   <input type="submit" value="Insert" onclick="document.Members.FormAction.value = 'insert';">
   <input type="hidden" value="insert" name="FormAction"/>
<? } ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Update" onclick="document.Members.FormAction.value = 'update';">
   
 <? } ?>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Delete" onclick="document.Members.FormAction.value = 'delete';">
   <? } ?>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.Members.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="Members">
  
  <input type="hidden" name="Trn_member_login" value="<?= $Trn_member_login ?>">
  <input type="hidden" name="PK_member_id" value="<?= $pmember_id ?>">  
  <input type="hidden" name="member_id" value="<?= tohtml($fldmember_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>