<?php
 /*********************************************************************************
 *          Filename: BookDetail.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "BookDetail.php";



check_security(1);

$sDetailErr = "";
$sOrderErr = "";
$sRatingErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Detail":
    Detail_action($sAction);
  break;
  case "Order":
    Order_action($sAction);
  break;
  case "Rating":
    Rating_action($sAction);
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
<? Detail_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Order_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Rating_Show() ?>
    
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



function Detail_action($sAction)
{
  global $db;
  global $sForm;
  global $sDetailErr;
  
  $sParams = "";
  $sActionFileName = "ShoppingCart.php";

  
  $sParams = "?";
  $sParams .= "item_id=" . tourl(get_param("Trn_item_id"));

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName . $sParams); 

  

  //-- Create SQL statement
  $sSQL = "";
  
  if(strlen($sDetailErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName . $sParams);
  
}



function Detail_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sDetailErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $flditem_id = "";
  $fldname = "";
  $fldauthor = "";
  $fldcategory_id = "";
  $fldprice = "";
  $fldimage_url = "";
  $fldnotes = "";
  $fldproduct_url = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Detail">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Book Detail</font></td></tr>
   <? if ($sDetailErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sDetailErr ?></font></td></tr><? } ?>
<? 

  if($sDetailErr == "")
  {
    //-- Get primary key and form parameters
    $flditem_id = get_param("item_id");
    $Trn_item_id = get_param("item_id");
    $pitem_id = get_param("item_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $flditem_id = strip(get_param("item_id"));
    $Trn_item_id = get_param("Trn_item_id");
    $pitem_id = get_param("PK_item_id");
  }

  
  if( !strlen($pitem_id)) $bPK = false;
  
  $sWhere .= "item_id=" . tosql($pitem_id, "Number");
  $PK_item_id = $pitem_id;

  $sSQL = "select * from items where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Detail"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $flditem_id = $db->f("item_id");
    $fldname = $db->f("name");
    $fldauthor = $db->f("author");
    $fldcategory_id = $db->f("category_id");
    $fldprice = $db->f("price");
    $fldimage_url = $db->f("image_url");
    $fldnotes = $db->f("notes");
    $fldproduct_url = $db->f("product_url");
  }

  else
  {
    if($sDetailErr == "")
    {
      $flditem_id = tohtml(get_param("item_id"));
    }
  }//-- Set lookup fields
  $fldcategory_id = dlookup("categories", "name", "category_id=" . tosql($fldcategory_id, "Number"));
  if($sDetailErr == "")
  {
$fldimage_url="<img border=0 src=" . $fldimage_url . ">";
$fldproduct_url="Review this book on Amazon.com";
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Title</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldname)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Author</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldauthor)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Category</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldcategory_id)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Price</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldprice)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Picture</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><a href="<?=$db->f("product_url") ?>"><font style="font-size: 10pt; color: #000000"><?= $fldimage_url ?></font></a>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Notes</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=$fldnotes?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000"></font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><a href="<?=$db->f("product_url") ?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldproduct_url) ?></font></a>&nbsp;</font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Detail"))) { ?>

<? } ?>

 
   <input type="hidden" name="FormName" value="Detail">
  
  <input type="hidden" name="Trn_item_id" value="<?= $Trn_item_id ?>">
  <input type="hidden" name="Rqd_item_id" value="<?= $Rqd_item_id ?>";>
  <input type="hidden" name="PK_item_id" value="<?= $pitem_id ?>">  
  <input type="hidden" name="item_id" value="<?= tohtml($flditem_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}





function Order_action($sAction)
{
  global $db;
  global $sForm;
  global $sOrderErr;
  
  $sParams = "";
  $sActionFileName = "ShoppingCart.php";

  

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName); 

  
  $fldUserID = get_session("UserID");
  $fldquantity = get_param("quantity");
  $flditem_id = get_param("item_id");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldquantity))
      $sOrderErr .= "The value in field Quantity is required.<br>";
    
    if(!is_number($fldquantity))
      $sOrderErr .= "The value in field Quantity is incorrect.<br>";
    
    if(!is_number($flditem_id))
      $sOrderErr .= "The value in field item_id is incorrect.<br>";
    

    if(strlen($sOrderErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "insert":
      
        $sSQL = "insert into orders (" . 
          "member_id," . 
          "quantity," . 
          "item_id)" . 
          " values (" . 
          tosql($fldUserID, "Number") . "," .
          tosql($fldquantity, "Number") . "," .
          tosql($flditem_id, "Number") . ")";
    break;
  }

  if(strlen($sOrderErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName);
  
}



function Order_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sOrderErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $fldorder_id = "";
  $fldquantity = "";
  $flditem_id = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Order">
   
   <? if ($sOrderErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sOrderErr ?></font></td></tr><? } ?>
<? 

  if($sOrderErr == "")
  {
    //-- Get primary key and form parameters
    $flditem_id = get_param("item_id");
    $porder_id = get_param("order_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $fldorder_id = strip(get_param("order_id"));
    $fldquantity = strip(get_param("quantity"));
    $flditem_id = strip(get_param("item_id"));
    $porder_id = get_param("PK_order_id");
  }

  
  if( !strlen($porder_id)) $bPK = false;
  
  $sWhere .= "order_id=" . tosql($porder_id, "Number");
  $PK_order_id = $porder_id;

  $sSQL = "select * from orders where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Order"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $fldorder_id = $db->f("order_id");
    $flditem_id = $db->f("item_id");
    if($sOrderErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldquantity = $db->f("quantity");
    }
  }

  else
  {
    if($sOrderErr == "")
    {
      $flditem_id = tohtml(get_param("item_id"));
      $fldquantity= "1";
    }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Quantity</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="quantity" maxlength="10" value="<?= tohtml($fldquantity) ?>" size="10" ></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Order"))) { ?>

<? if (!$bPK) { ?>
   <input type="submit" value="Add to Shopping Cart" onclick="document.Order.FormAction.value = 'insert';">
   <input type="hidden" value="insert" name="FormAction"/>
<? } ?>

<? } else { ?>
  <input type="hidden" value="" name="FormAction"/>
 
<? } ?>

 
   <input type="hidden" name="FormName" value="Order">
  
  <input type="hidden" name="PK_order_id" value="<?= $porder_id ?>">  
  <input type="hidden" name="order_id" value="<?= tohtml($fldorder_id) ?>">
  <input type="hidden" name="item_id" value="<?= tohtml($flditem_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}





function Rating_action($sAction)
{
  global $db;
  global $sForm;
  global $sRatingErr;
  
  $sParams = "";
  $sActionFileName = "BookDetail.php";

  
  $sParams = "?";
  $sParams .= "item_id=" . tourl(get_param("Trn_item_id"));

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName . $sParams); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKitem_id = get_param("PK_item_id");
    
    $sWhere .= "item_id=" . tosql($pPKitem_id, "Number");
    
  }
  
  $fldrating = get_param("rating");
  $fldrating_count = get_param("rating_count");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldrating))
      $sRatingErr .= "The value in field Your Rating is required.<br>";
    
    if(!is_number($fldrating))
      $sRatingErr .= "The value in field Your Rating is incorrect.<br>";
    
    if(!is_number($fldrating_count))
      $sRatingErr .= "The value in field rating_count is incorrect.<br>";
    

    if(strlen($sRatingErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "update":
      
$sSQL = "update items set rating=rating+" . get_param("rating") . ", rating_count=rating_count+1 where item_id=" . get_param("item_id");
      if($sSQL == "")
      {
        $sSQL = "update items set " .
          "rating=" . tosql($fldrating, "Number") .
          ",rating_count=" . tosql($fldrating_count, "Number");
        $sSQL .= " where " . $sWhere;
      }
    break;
  
  }

  if(strlen($sRatingErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName . $sParams);
  
}



function Rating_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sRatingErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $flditem_id = "";
  $fldrating_view = "";
  $fldrating_count_view = "";
  $fldrating = "";
  $fldrating_count = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Rating">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Rating</font></td></tr>
   <? if ($sRatingErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sRatingErr ?></font></td></tr><? } ?>
<? 

  if($sRatingErr == "")
  {
    //-- Get primary key and form parameters
    $flditem_id = get_param("item_id");
    $Trn_item_id = get_param("item_id");
    $pitem_id = get_param("item_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $flditem_id = strip(get_param("item_id"));
    $fldrating = strip(get_param("rating"));
    $fldrating_count = strip(get_param("rating_count"));
    $Trn_item_id = get_param("Trn_item_id");
    $pitem_id = get_param("PK_item_id");
  }

  
  if( !strlen($pitem_id)) $bPK = false;
  
  $sWhere .= "item_id=" . tosql($pitem_id, "Number");
  $PK_item_id = $pitem_id;

  $sSQL = "select * from items where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Rating"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $flditem_id = $db->f("item_id");
    $fldrating_view = $db->f("rating");
    $fldrating_count_view = $db->f("rating_count");
    $fldrating_count = $db->f("rating_count");
    if($sRatingErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldrating = $db->f("rating");
    }
  }

  else
  {
    if($sRatingErr == "")
    {
      $flditem_id = tohtml(get_param("item_id"));
    }
  }
  if($sRatingErr == "")
  {
if ($fldrating_view == 0)
      {
        $fldrating_view = "Not rated yet";
        $fldrating_count_view = "";
      }
      else
      {
        $fldrating_view = "<img src=\"images/" . round($fldrating/$fldrating_count) . "stars.gif\">";
      }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Current Rating</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=$fldrating_view?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Total Votes</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><?=tohtml($fldrating_count_view)?>&nbsp;</font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Your Rating</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><select name="rating"><?= get_lov_options('1;Deficient;2;Regular;3;Good;4;Very Good;5;Excellent',false,true,$fldrating);?></select></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Rating"))) { ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Vote" onclick="document.Rating.FormAction.value = 'update';">
   
 <? } ?>
 
<? } ?>

 
   <input type="hidden" name="FormName" value="Rating">
  
  <input type="hidden" name="Trn_item_id" value="<?= $Trn_item_id ?>">
  <input type="hidden" name="PK_item_id" value="<?= $pitem_id ?>">  
  <input type="hidden" name="item_id" value="<?= tohtml($flditem_id) ?>">
  <input type="hidden" name="rating_count" value="<?= tohtml($fldrating_count) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>