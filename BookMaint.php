<?php
 /*********************************************************************************
 *          Filename: BookMaint.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "BookMaint.php";



check_security(2);

$sBookErr = "";
$sAction = get_param("FormAction");
$sForm = get_param("FormName");

//-- handling actions
switch ($sForm)
{
  case "Book":
    Book_action($sAction);
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
<? Book_Show() ?>
    <SCRIPT Language="JavaScript">
if (document.forms["Book"])
document.Book.onsubmit=delconf;
function delconf() {
if (document.Book.FormAction.value == 'delete')
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



function Book_action($sAction)
{
  global $db;
  global $sForm;
  global $sBookErr;
  
  $sParams = "";
  $sActionFileName = "AdminBooks.php";

  
  $sParams = "?";
  $sParams .= "category_id=" . tourl(get_param("Trn_category_id")) . "&";
  $sParams .= "is_recommended=" . tourl(get_param("Trn_is_recommended"));

  $sWhere = "";
  $bErr = false;

  if($sAction == "cancel")
    header("Location: " . $sActionFileName . $sParams); 

  
  if($sAction == "update" || $sAction == "delete") 
  {
    $pPKitem_id = get_param("PK_item_id");
    
    $sWhere .= "item_id=" . tosql($pPKitem_id, "Number");
    
  }
  
  $fldname = get_param("name");
  $fldauthor = get_param("author");
  $fldcategory_id = get_param("category_id");
  $fldprice = get_param("price");
  $fldproduct_url = get_param("product_url");
  $fldimage_url = get_param("image_url");
  $fldnotes = get_param("notes");
  $fldis_rec = get_checkbox_value(get_param("is_rec"), "1", "0", "Number");
  if($sAction == "insert" || $sAction == "update") 
  {
    if(!strlen($fldname))
      $sBookErr .= "The value in field Title is required.<br>";
    
    if(!strlen($fldcategory_id))
      $sBookErr .= "The value in field Category is required.<br>";
    
    if(!strlen($fldprice))
      $sBookErr .= "The value in field Price is required.<br>";
    
    if(!is_number($fldcategory_id))
      $sBookErr .= "The value in field Category is incorrect.<br>";
    
    if(!is_number($fldprice))
      $sBookErr .= "The value in field Price is incorrect.<br>";
    

    if(strlen($sBookErr)) return;
  }
  

  //-- Create SQL statement
  $sSQL = "";
  
  switch(strtolower($sAction)) 
  {
    case "insert":
      
        $sSQL = "insert into items (" . 
          "name," . 
          "author," . 
          "category_id," . 
          "price," . 
          "product_url," . 
          "image_url," . 
          "notes," . 
          "is_recommended)" . 
          " values (" . 
          tosql($fldname, "Text") . "," .
          tosql($fldauthor, "Text") . "," .
          tosql($fldcategory_id, "Number") . "," .
          tosql($fldprice, "Number") . "," .
          tosql($fldproduct_url, "Text") . "," .
          tosql($fldimage_url, "Text") . "," .
          tosql($fldnotes, "Text") . "," .
          $fldis_rec . ")";
    break;
    case "update":
      
        $sSQL = "update items set " .
          "name=" . tosql($fldname, "Text") .
          ",author=" . tosql($fldauthor, "Text") .
          ",category_id=" . tosql($fldcategory_id, "Number") .
          ",price=" . tosql($fldprice, "Number") .
          ",product_url=" . tosql($fldproduct_url, "Text") .
          ",image_url=" . tosql($fldimage_url, "Text") .
          ",notes=" . tosql($fldnotes, "Text") .
          ",is_recommended=" . $fldis_rec;
        $sSQL .= " where " . $sWhere;
    break;
  
    case "delete":
      
        $sSQL = "delete from items where " . $sWhere;
    break;
  
  }

  if(strlen($sBookErr)) return;
  //-- Execute SQL query
  $db->query($sSQL);
  
  header("Location: " . $sActionFileName . $sParams);
  
}



function Book_Show()
{
  global $sFileName;
  global $sAction;
  global $db;
  global $sForm;
  global $sBookErr;

  global $styles;

  $sWhere = "";
  
  $bPK = true;  //-- primary key indication

  //-- begin block of initialization variables
  $flditem_id = "";
  $fldname = "";
  $fldauthor = "";
  $fldcategory_id = "";
  $fldprice = "";
  $fldproduct_url = "";
  $fldimage_url = "";
  $fldnotes = "";
  $fldis_rec = "";
  //-- end block

?>
   
   <table style="">
   <form method="POST" action="<?= $sFileName ?>" name="Book">
   <tr><td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Book</font></td></tr>
   <? if ($sBookErr) { ?> <tr><td style="background-color: #FFFFFF; border-width: 1" colspan="2"><font style="font-size: 10pt; color: #000000"><?= $sBookErr ?></font></td></tr><? } ?>
<? 

  if($sBookErr == "")
  {
    //-- Get primary key and form parameters
    $fldcategory_id = get_param("category_id");
    $flditem_id = get_param("item_id");
    $fldis_recommended = get_param("is_recommended");
    $Trn_category_id = get_param("category_id");
    $Trn_is_recommended = get_param("is_recommended");
    $pitem_id = get_param("item_id");
  }
  else
  {
    //-- Get primary key, form parameters and form's fields
    $flditem_id = strip(get_param("item_id"));
    $fldname = strip(get_param("name"));
    $fldauthor = strip(get_param("author"));
    $fldcategory_id = strip(get_param("category_id"));
    $fldprice = strip(get_param("price"));
    $fldproduct_url = strip(get_param("product_url"));
    $fldimage_url = strip(get_param("image_url"));
    $fldnotes = strip(get_param("notes"));
    $fldis_rec = strip(get_param("is_rec"));
    $Trn_category_id = get_param("Trn_category_id");
    $Trn_is_recommended = get_param("Trn_is_recommended");
    $pitem_id = get_param("PK_item_id");
  }

  
  if( !strlen($pitem_id)) $bPK = false;
  
  $sWhere .= "item_id=" . tosql($pitem_id, "Number");
  $PK_item_id = $pitem_id;

  $sSQL = "select * from items where " . $sWhere;
  if($bPK && !($sAction == "insert" && $sForm == "Book"))
  {
    $db->query($sSQL);
    $db->next_record();
    
    $flditem_id = $db->f("item_id");
    if($sBookErr == "") 
    {
      //-- Load data from database when form is displayed for the first time
    
      $fldname = $db->f("name");
      $fldauthor = $db->f("author");
      $fldcategory_id = $db->f("category_id");
      $fldprice = $db->f("price");
      $fldproduct_url = $db->f("product_url");
      $fldimage_url = $db->f("image_url");
      $fldnotes = $db->f("notes");
      $fldis_rec = $db->f("is_recommended");
    }
  }

  else
  {
    if($sBookErr == "")
    {
      $flditem_id = tohtml(get_param("item_id"));
      $fldcategory_id = tohtml(get_param("category_id"));
      $fldis_rec = tohtml(get_param("is_recommended"));
      $fldis_rec= "0";
    }
  }
    //-- show fields
    ?>
  <tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Title</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="name" maxlength="100" value="<?= tohtml($fldname) ?>" size="30" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Author</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="author" maxlength="100" value="<?= tohtml($fldauthor) ?>" size="30" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Category</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000"><select name="category_id"><?= get_options("select category_id, name from categories order by 2",false,true,$fldcategory_id);?></select></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Price</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="price" maxlength="10" value="<?= tohtml($fldprice) ?>" size="10" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Product URL</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="product_url" maxlength="100" value="<?= tohtml($fldproduct_url) ?>" size="40" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Image URL</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <input type="text" name="image_url" maxlength="100" value="<?= tohtml($fldimage_url) ?>" size="40" ></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Notes</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
  <textarea name="notes" cols="60" rows="8"><?= tohtml($fldnotes) ?></textarea></font>
       </td>
     </tr>
<tr>
       <td style="background-color: #FFEAC5; border-style: inset; border-width: 0">
         <font style="font-size: 10pt; color: #000000">Recommended</font>
       </td>
       <td style="background-color: #FFFFFF; border-width: 1">
         <font style="font-size: 10pt; color: #000000">
         <? if(strtolower(tohtml($fldis_rec)) == strtolower("1")) { ?>
           <input type="checkbox" CHECKED name="is_rec">
         <? } else { ?>
           <input type="checkbox" name="is_rec">
         <? } ?></font>
       </td>
     </tr>

    <tr align="right"><td colspan="2" align="right">
    

<? if (!($bPK && !($sAction=="insert" && $sForm=="Book"))) { ?>

<? if (!$bPK) { ?>
   <input type="submit" value="Add" onclick="document.Book.FormAction.value = 'insert';">
   <input type="hidden" value="insert" name="FormAction"/>
<? } ?>

<? } else { ?>
  <input type="hidden" value="update" name="FormAction"/>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Update" onclick="document.Book.FormAction.value = 'update';">
   
 <? } ?>
 
 <? if ($bPK) { ?>
   <input type="submit" value="Delete" onclick="document.Book.FormAction.value = 'delete';">
   <? } ?>
 
<? } ?>

 <input type="submit" value="Cancel" onclick="document.Book.FormAction.value = 'cancel';">
   <input type="hidden" name="FormName" value="Book">
  
  <input type="hidden" name="Trn_category_id" value="<?= $Trn_category_id ?>">
  <input type="hidden" name="Trn_is_recommended" value="<?= $Trn_is_recommended ?>">
  <input type="hidden" name="PK_item_id" value="<?= $pitem_id ?>">  
  <input type="hidden" name="item_id" value="<?= tohtml($flditem_id) ?>">

  </td></tr>
  </form>
  </table>
<?
  
}



?>