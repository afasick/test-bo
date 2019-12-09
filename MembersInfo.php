<?php
 /*********************************************************************************
 *          Filename: MembersInfo.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "MembersInfo.php";



check_security(2);

$sRecordErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Record":
    Record_action($sAction);
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
<? Record_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Orders_Show() ?>
    
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



function Record_action($sAction)
{
  global $db;
  global $sForm;
  global $sRecordErr;
  
  $sParams = "";
  $sActionFileName = "AdminMenu.php";

  

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName); 

  

  //-- Create SQL statement
  $sSQL = "";
  
  if(strlen($sRecordErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName);
  
}



function Record_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sRecordErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldmember_id = "";
  $fldmember_login = "";
  $fldmember_level = "";
  $fldname = "";
  $fldlast_name = "";
  $fldemail = "";
  $fldphone = "";
  $fldaddress = "";
  $fldnotes = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Record">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Member Info</font></td></tr>
   <? if ($sRecordErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sRecordErr ?></font></td></tr><? } ?>
<? 

  if($sRecordErr == "")
  {
    //-- Get primary key and form parameters
    $pmember_id = get_param("member_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldmember_id = strip(get_param("member_id"));
    $pmember_id = get_param("PK_member_id");
  }

  
  if( !strlen($pmember_id)) $bPK = false;
  
  $sWhere .= "member_id=" . tosql($pmember_id, "Number");
  $PK_member_id = $pmember_id;

  $sSQL = "select * from members where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Record"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldmember_id = $db->f("member_id");
    $fldmember_login = $db->f("member_login");
    $fldmember_level = $db->f("member_level");
    $fldname = $db->f("first_name");
    $fldlast_name = $db->f("last_name");
    $fldemail = $db->f("email");
    $fldphone = $db->f("phone");
    $fldaddress = $db->f("address");
    $fldnotes = $db->f("notes");
  }

  else
  {
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Login</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><a href="MembersRecord.php?member_id=<?= tourl($db->f("member_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldmember_login) ?></font></a>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Level</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldmember_level)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">First Name</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldname)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Last Name</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldlast_name)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Email</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldemail)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Phone</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldphone)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Address</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldaddress)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Notes</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldnotes)?>&nbsp;</font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Record"))) { ?>

<? } ?>

 
   <input type="hidden" name="FormName" value="Record">
  
  <input type="hidden" name="PK_member_id" value="<?= $pmember_id ?>">  
  <input type="hidden" name="member_id" value="<?= tohtml($fldmember_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}




function Orders_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sOrdersErr; //-- error string

  
  //-- transit parameters
  $transit_params = "member_id=" . tourl(strip(get_param("member_id"))) . "&";
  //-- form parameters
  $form_params = "member_id=" . tourl(get_param("member_id")) . "&";
  $bReq = true; //-- there are required parameters

  $HasParam = false;

  $iSort = get_param("FormOrders_Sorting");
  $iSorted = get_param("FormOrders_Sorted");

  //-- process sort commands
  $sDirection = "";
  $sSortParams = "";
  if($iSort)
  {
    if($iSort == $iSorted)
    {
      $form_sorting = "";
      $sDirection = " DESC";
      $sSortParams = "FormOrders_Sorting=" . $iSort . "&FormOrders_Sorted=" . $iSort . "&";
    }
    else
    {
      $form_sorting = $iSort;
      $sDirection = " ASC";
      $sSortParams = "FormOrders_Sorting=" . $iSort . "&FormOrders_Sorted=" . "&";
    }
    
    if ($iSort == 1) $sOrder = " order by o.order_id" . $sDirection;
    if ($iSort == 2) $sOrder = " order by i.name" . $sDirection;
    if ($iSort == 3) $sOrder = " order by o.quantity" . $sDirection;
    if (!strlen($sOrder))  $sDirection = "";
  }
  

//-- table header
?>
     <table style="">
      <tr>
       <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="3"><a name="Orders"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Shopping Cart</font></a></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormOrders_Sorting=1&FormOrders_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Order</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormOrders_Sorting=2&FormOrders_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Item</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormOrders_Sorting=3&FormOrders_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Quantity</font></a></td>
      </tr>
<?

  $sWhere = "";
  
  //-- Check member_id parameter and create a valid sql for where clause
  
  $pmember_id = get_param("member_id");
  if(is_number($pmember_id) && strlen($pmember_id))
    $pmember_id = round($pmember_id);
  else 
    $pmember_id = "";
  if(strlen($pmember_id)) 
  {
    $HasParam = true;
    $sWhere .= "o.member_id=" . $pmember_id;
  }
  else
    $bReq = false;
  //-- populate arrays for list of values
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " AND (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "select o.item_id as o_item_id, " . 
    "o.member_id as o_member_id, " . 
    "o.order_id as o_order_id, " . 
    "o.quantity as o_quantity, " . 
    "i.item_id as i_item_id, " . 
    "i.name as i_name " . 
    " from orders o, items i" . 
    " where i.item_id=o.item_id  ";
  
  $sSQL = $sSQL . $sWhere . $sOrder;

  //-- insert button
  
//-- required parameters
  if(!$bReq)
  {
    ?>
     <tr>
      <td colspan="3" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records></font></td>
     </tr>
    </table>
    <?
    return;
  }


  //-- do SQL query
  $db->query($sSQL);
  
  $is_next_record=false;

  //-- show records
  if($db->next_record())
  {
    //-- default values
    

    //-- display rows
    do
    {
      //-- retrieve data from the record
      $fldorder_id = $db->f("o_order_id");
      $flditem_id = $db->f("i_name");
      $fldquantity = $db->f("o_quantity");

      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><a href="OrdersRecord.php?order_id=<?= tourl($db->f("o_order_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldorder_id) ?></font></a>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($flditem_id)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldquantity)?>&nbsp;</font></td>
      </tr>
    <?
    $is_next_record = @$db->next_record();
    } while($is_next_record );
  }
  else //-- there are no records
  {
  //$db->num_rows() == 0 || ($iPage - 1)*$RecordsPerPage >= $db->num_rows())
    ?>
      <tr><td colspan="3" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records</font></td></tr>


      </table>
    <?
    return;
  }

 

  //-- the end of the last row and the end of the table
  ?>
    </table>
  <?

 
}

?>