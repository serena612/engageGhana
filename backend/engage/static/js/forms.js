// Contact Form Submit
$(document).on("submit", "#contact-form", function (e) {
    e.preventDefault();
    var form = $(this);
    var data = getFormData(form);

    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);

    $.ajax({
        url: post_contact_engage_url,
        type: data.method,
        data: data.data
    }).done(function (response) {
        form.find(".response-msg").html("Thank you for your message. We will reply as soon as we can").show();
        form.trigger("reset");
        setBtnLoading(btn, false);
    }).fail(function (e) {
        console.log("e", e);
        form.find(".response-msg").html("Error, Please check your internet connection").show();
        setBtnLoading(btn, false);
    });
})


// Support Form Submit
$(document).on("submit", "#support-form", function (e) {
    e.preventDefault();
    var form = $(this);
    var data = getFormData(form);
    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);

    $.ajax({
        url: post_contact_support_url,
        type: data.method,
        data: data.data
    }).done(function (response) {
        form.find(".response-msg").html("Thank you for your message. We will reply as soon as we can").show();
        form.trigger("reset");
        setBtnLoading(btn, false);
    }).fail(function (e) {
        form.find(".response-msg").html("Error, Please check your internet connection").show();
        setBtnLoading(btn, false);
    });

})


//login form 
$(document).on("submit", ".login-form", function (e) {
    e.preventDefault();
    var form = $(this);
    var form_data = getFormData(form);
    var response_msg = form.find(".response-msg");
    response_msg.hide();
    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);
    if(checkValidMtnNumber(form_data.data.phone_number)) {
        // if(form_data.data.phone_number.indexOf('234')==-1){
        //     var firststr = form_data.data.phone_number;
        //     if(form_data.data.phone_number.indexOf('0')==0){ 
        //         firststr = form_data.data.phone_number.substring(1,form_data.data.phone_number.length);
        //         if(form_data.data.phone_number.length==14){
        //             firststr = form_data.data.phone_number.substring(2,form_data.data.phone_number.length);
        //         }
        //         form_data.data.phone_number='234'+firststr;
        //     }
        //     else
        //         form_data.data.phone_number='234'+firststr;
        // }
        
            if(form_data.data.phone_number!=undefined){
                var firststr = form_data.data.phone_number;
                if(form_data.data.phone_number.length == 11){ 
                    form_data.data.phone_number = '234'+form_data.data.phone_number.slice(1);
                }
                else if(form_data.data.phone_number.length == 14 && form_data.data.phone_number.indexOf('+')==0){ 
                    form_data.data.phone_number = form_data.data.phone_number.slice(1);
                }
                else if(form_data.data.phone_number.length == 14 && form_data.data.phone_number.indexOf('+')==-1){ 
                    var code = form_data.data.phone_number.slice(0,3);
                    var firststr =  form_data.data.phone_number.slice(3,4);
                    if(firststr=='0')
                    {
                        form_data.data.phone_number = code+form_data.data.phone_number.slice(4,form_data.data.phone_number.length);
                    }
                    else{
                        form_data.data.phone_number =code+form_data.data.phone_number.slice(3,form_data.data.phone_number.length);
                    }
                    
                }
                else if(form_data.data.phone_number.length == 15 && form_data.data.phone_number.indexOf('00')==0){ 
                    form_data.data.phone_number = form_data.data.phone_number.slice(2); 
                }   
            }
    }  
    
   
    postLogin(form_data.data).then(res => {
        //form.trigger("reset");
        setBtnLoading(btn, false);
        form.hide();
        $(".login-otp-form").show();
        $(".login-otp-form").find('.input1').focus();
    }).catch(e => {
        if(e.status==472) //406 ?
        response_msg.html('The number you have provided is invalid!').show();
        else if(e.status==458)
        response_msg.html('The max allowed sent pin codes have been reached! Please try again tomorrow.').show();
        else if(e.status==555)
        response_msg.html('No connection available, please try again later.').show();
        else
        response_msg.html('Something went wrong. Please try again later.').show();  // Error code: '+e.status
        setBtnLoading(btn, false);

        
        
    });
})


//login otp form
$(document).on("submit", ".login-otp-form", function (e) {
    e.preventDefault();
    var form = $(this);
    var form_data = getFormData(form);
    form_data.data.mobile = $('.login-form').find('.input1').val();
    if(checkValidMtnNumber(form_data.data.mobile)) {
        // if(form_data.data.mobile.indexOf('234')==-1){
        //     var firststr = form_data.data.mobile;
        //     if(form_data.data.mobile.indexOf('0')==0){ 
        //         firststr = form_data.data.mobile.substring(1,form_data.data.mobile.length);
        //         form_data.data.mobile='234'+firststr;
        //     }
        //     else
        //         form_data.data.mobile='234'+firststr;
        // }
        if(form_data.data.mobile!=undefined){
            var firststr = form_data.data.mobile;
            if(form_data.data.mobile.length == 11){ 
                form_data.data.mobile = '234'+form_data.data.mobile.slice(1);
            }
            else if(form_data.data.mobile.length == 14 && form_data.data.mobile.indexOf('+')==0){ 
                form_data.data.mobile = form_data.data.mobile.slice(1);
            }
            else if(form_data.data.mobile.length == 14 && form_data.data.mobile.indexOf('+')==-1){ 
                var code = form_data.data.mobile.slice(0,3);
                var firststr =  form_data.data.mobile.slice(3,4);
                if(firststr=='0')
                {
                    form_data.data.mobile = code+form_data.data.mobile.slice(4,form_data.data.mobile.length);
                }
                else{
                    form_data.data.mobile =code+form_data.data.mobile.slice(3,form_data.data.mobile.length);
                }
                
            }
            else if(form_data.data.mobile.length == 15 && form_data.data.mobile.indexOf('00')==0){ 
                form_data.data.mobile = form_data.data.mobile.slice(2); 
            }   
        }
    }  
    var response_msg = form.find(".response-msg");
    response_msg.hide();
    // Re-enable this to restore old functiionality
    // if(form_data.data.code!='123456'){  
    //     response_msg.html('Please enter a valid pincode!').show();
    //     return;
    // }
    response_msg.html('').hide();
    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);

    postLoginOTP(form_data.data).then(res => {
        //console.log(res);
        $('.login-form').trigger("reset");
        setBtnLoading(btn, false);
    }).catch(e => {
        console.log("e", e);
        if(e.status==478 || e.status==459)
        response_msg.html('Invalid Pincode!').show();
        else if(e.status==471) //406 ?
        response_msg.html('Exceed maximum allowed attempts! Please try again later.').show();
        else if(e.status==472)
        response_msg.html('Invalid Phone Number provided!').show();
        else if(e.status==480)
        response_msg.html('Your subscription has ended. Please renew your subscription <a href="/register">here</a>.').show();
        else if(e.status==481) 
        response_msg.html('Your pincode has expired. Please try again.').show();
        else if(e.status==514){
            $('#login-modal').modal("hide");
            // $('.login-form').trigger("reset");
            $('#wait-modal').modal("show");
             get_wait_modal();
        }
        else
        response_msg.html('Something went wrong. Please try again later.').show();  //  Error code: '+e.status
        setBtnLoading(btn, false);
    });
})
//search array for specific values
function in_array(value, array){
	var index = array.indexOf(value);
	if(index == -1){
		return false;
	}else{
		return index;
	}
}

function get_wait_modal() {
    $.ajax({
        url:"/wait", //the page containing python script
        type: "GET", //request type,
        data: {},
        async:true,
        beforeSend: function(){
                //$('#waitmodalcontent').html("<img class='loading-img' src='/static/img/loading1.gif' /><br><div style='text-align: center;'>Loading...</div>");
                $("#wait-modal .preload").removeClass("d-none");
              },
        success:function(result){
           // $('#waitmodalcontent').html(result); 
           //alert("res:" + result);
           //$("#wait-modal .preload").addClass("d-none");
           //$(".please_wait").addClass("d-none");
            
           
            // $('#waitmodalcontent').find(".success-bd").find(".desc").html(result);
            // $('#waitmodalcontent').find(".error-bd").find(".desc").html(result);
            $('#waitmodalcontent').find(".desc").html(result);
                      
        }
        
    });
}
function checkValidMtnNumber(number){
    var valid=true;
    var telcoPrefixes = [803, 806,703, 706, 813, 816, 810,  814, 903];
    var xpref=[7025, 7026, 703, 704, 706, 803, 806, 810, 813, 814, 816, 903, 906,913,916,102]; //added 102 for test


    //get value from textbox
	phoneInputValue = number;

	//get value length
	var inputLength = phoneInputValue.length;

	//if length is less than the required length of 14
	if(inputLength < 11 || inputLength == 12){

		valid=false;

	//if length is equal to 11 (070xxxxxxxx)
	}else if(inputLength === 11){

				//get mobile number prefix - 706 or 703 - depending on telco
				mobilePrefix = Number(phoneInputValue.substr(1,3));
                if(mobilePrefix==702)
                mobilePrefix = Number(phoneInputValue.substr(1,4));
				firstFigure = Number(phoneInputValue[0]);

				//check if mobile prefix exists in telcoPrefixes array
				checkArray = in_array(mobilePrefix, xpref);
				if(checkArray === false){
					valid=false;
				}else if(checkArray >=0 && firstFigure === 0){
					valid=true;
				}else{
					valid=false;

				}

	//if length is equal to 13 (23470xxxxxxxx)
	}
    else if(inputLength === 13){

				//get mobile number prefix - 706 or 703 - depending on telco
				firststr=Number(phoneInputValue.substr(3,3));
                if(firststr < 100)
               {valid=false;return valid;}
                else 
                mobilePrefix = Number(phoneInputValue.substr(3,3));
				//get dialling code from mobile number
				dialingCode = Number(phoneInputValue.substr(0,3));
                if(mobilePrefix==702)
                mobilePrefix = Number(phoneInputValue.substr(3,4));
				//check if mobile prefix exists in telcoPrefixes array		
				checkArray = in_array(mobilePrefix, xpref);
				if(checkArray === false){
					
					valid=false;

				}else if((checkArray >= 0) && (dialingCode === 234)){

					valid=true;

				}else{

					valid=false;
				}

//if length is equal to 14 (+23470xxxxxxxx)
	}else if(inputLength === 14){

				//get mobile number prefix from entered value
				mobilePrefix = Number(phoneInputValue.slice(4,7));

				//get dialling code from mobile number - +234
				dialingCode = phoneInputValue.slice(0,4);
                if(dialingCode!="+234"){
                    dialingCode=phoneInputValue.slice(0,3);
                    var firstdigit =  Number(phoneInputValue.slice(3,4));
                    if(firstdigit==0){
                        mobilePrefix = Number(phoneInputValue.slice(4,7));
                        if(mobilePrefix==702)
                        mobilePrefix = Number(phoneInputValue.slice(4,8));
                    }
                    else{
                        valid=false;return valid;
                    }
                    
                }
                else{
                    var firststr=Number(phoneInputValue.slice(4,5));
                    if(firststr!=0)
                    {
                        mobilePrefix = Number(phoneInputValue.slice(4,7)); 
                        if(mobilePrefix==702){
                            mobilePrefix=Number(phoneInputValue.slice(4,8));
                        }
                    }
                    else{
                        valid=false;
                        return valid;
                    }

                }

				//check if prefix exists in mobile prefix array
				checkArray = in_array(mobilePrefix, xpref);

				//if prefix not found in array
				if(checkArray === false){
					valid=false;
				//if found in array
				}else if((checkArray >= 0) && ((dialingCode === "+234") || (dialingCode === "234"))){
					valid=true;
				}else{
					valid=false;
				}
	}
    else if(inputLength === 15){

        //get mobile number prefix from entered value

        firststr =  phoneInputValue.substring(0,2)
        if(firststr!='00')
        {
            valid=false;
            return valid;
        }

        firststr = Number(phoneInputValue.slice(5,6));
        if(firststr==0)
        {
            valid=false;
            return valid;
        }
        else{
            mobilePrefix = Number(phoneInputValue.slice(5,8));
            if(mobilePrefix==702)
               mobilePrefix=Number(phoneInputValue.slice(5,9));
        }


        //get dialling code from mobile number - +234
        dialingCode = phoneInputValue.slice(0,5);
       

        //check if prefix exists in mobile prefix array
        checkArray = in_array(mobilePrefix, xpref);

        //if prefix not found in array
        if(checkArray === false){
            valid=false;
        //if found in array
        }else if((checkArray >= 0) && (dialingCode === "00234")){
            valid=true;
        }else{
            valid=false;
        }
    }
    else if(inputLength > 14){
		valid=false;
	}

    return valid;
  
}
function isNumberx(evt, element) {

    var charCode = (evt.which) ? evt.which : event.keyCode

    if (
        (charCode != 45 || $(element).val().indexOf('-') != -1) &&      // Check minus and only once.
        (charCode != 46 || $(element).val().indexOf('.') != -1) &&      // Check dot and only once.
        (charCode < 48 || charCode > 57))
        return false;

    return true;
} 
$(document).ready(function(){
    $('.frmregister').find('.input1').keypress(function (e) {
        return isNumberx(event, this)
    });
})

// Register Form Submit
$(document).on("submit", ".frmregister", function (e) {
    e.preventDefault();
    var form = $(this);
    var data = getFormData(form);
    var response_msg = form.find(".response-msg");
    response_msg.hide();response_msg.html('');

    $(".sendcodemsg").html('').hide();
    
    var btn = form.find("button[type=submit]");
    if($('input[name="phone_number"]').css('display')!="none" && data.data.phone_number=="")
       return;
   
    if(!checkValidMtnNumber($('input[name="phone_number"]').val())) {
        //response_msg.html('Please enter a valid MTN number (i.e "0xx xxx xxxxx" or "234 xxx xxx xxxx")').show();
        response_msg.html(valid_number).show();
        return;
    }  
    else{
        response_msg.html('');
    }
    

    if(data.data.phone_number!=undefined){
        var firststr = data.data.phone_number;
        if(data.data.phone_number.length == 11){ 
            data.data.phone_number = '234'+data.data.phone_number.slice(1);
        }
        else if(data.data.phone_number.length == 14 && data.data.phone_number.indexOf('+')==0){ 
            data.data.phone_number = data.data.phone_number.slice(1);
        }
        else if(data.data.phone_number.length == 14 && data.data.phone_number.indexOf('+')==-1){ 
            var code = data.data.phone_number.slice(0,3);
            var firststr =  data.data.phone_number.slice(3,4);
            if(firststr=='0')
            {
                data.data.phone_number = code+data.data.phone_number.slice(4,data.data.phone_number.length);
            }
            else{
                data.data.phone_number =code+data.data.phone_number.slice(3,data.data.phone_number.length);
            }
            
        }
        else if(data.data.phone_number.length == 15 && data.data.phone_number.indexOf('00')==0){ 
            data.data.phone_number = data.data.phone_number.slice(2); 
        }   
    }

    setBtnLoading(btn, true);

    data.data.subscription = 'free';//$('#user_sub_mod').val();
    
    console.log("---aaa----");
    console.log(data.data);
    console.log("--aaa-----");
    $("#reg_code").val("");

    postRegister(data.data).then(res => {
        //form.trigger("reset");
        setBtnLoading(btn, false);
        form.hide();
        $('body').addClass('tab2');
        $(".register-otp-form").show();
        $(".sendcodemsg").html('A pin code has been sent to you. Please enter the pin code to proceed.').show(); 
             

    }).catch(e => {
        if(e.status==306)
        {
            $("#reg_code").val("1");
            $(".sendcodemsg").html('The mobile number you have provided already exists!').show();
        }
        else if(e.status==472) //406 ?
        $(".sendcodemsg").html('The number you have provided is invalid!').show();
        else if(e.status==458)
        $(".sendcodemsg").html('The max allowed sent pin codes have been reached! Please try again tomorrow.').show();
        else if(e.status==555)
        $(".sendcodemsg").html('No connection available, please try again later.').show();
        else
        $(".sendcodemsg").html('Something went wrong. Please try again later.').show();  //  Error code: '+e.status
        setBtnLoading(btn, false);
    });

})


//register otp form
$(document).on("submit", ".register-otp-form", function (e) {
    e.preventDefault();
    var form = $(this);
    var response_msg = form.find(".response-msg");
    var data = getFormData(form);
    data.data.phone_number = $('.frmregister').find('input[name="phone_number"]').val();
    data.data.refid = refid;
    if(data.data.phone_number!=undefined){
        var firststr = data.data.phone_number;
        if(data.data.phone_number.length == 11){ 
            data.data.phone_number = '234'+data.data.phone_number.slice(1);
        }
        else if(data.data.phone_number.length == 14 && data.data.phone_number.indexOf('+')==0){ 
            data.data.phone_number = data.data.phone_number.slice(1);
        }
        else if(data.data.phone_number.length == 14 && data.data.phone_number.indexOf('+')==-1){ 
            var code = data.data.phone_number.slice(0,3);
            var firststr =  data.data.phone_number.slice(3,4);
            if(firststr=='0')
            {
                data.data.phone_number = code+data.data.phone_number.slice(4,data.data.phone_number.length);
            }
            else{
                data.data.phone_number =code+data.data.phone_number.slice(3,data.data.phone_number.length);
            }
            
        }
        else if(data.data.phone_number.length == 15 && data.data.phone_number.indexOf('00')==0){ 
            data.data.phone_number = data.data.phone_number.slice(2); 
        }   
    }
    
    
    data.data.subscription = 'free'; //$('#user_sub_mod').val();//$('.frmregister').find('select[name="subscription"]').val();
    
    // if($('input[name="code"]').val()!="123456"){
    //     response_msg.html('Please enter a valid pincode!').show();
    //     return;
    // }
    // else{
    //     response_msg.html('').hide();
    // }
    
    //frmregister.reset(); //  <--------------------  I think this should be commented
    
    response_msg.hide();
    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);

    postRegisterOTP(data.data).then(res => {
        localStorage.removeItem("last_profile_edit");
        location.href = location.href.replace('/register','');
    }).catch(e => {
        console.log("e", e);
        if(e.status==478 || e.status==459)
        response_msg.html('Invalid Pincode!').show();
        else if(e.status==471) //406 ?
        response_msg.html('Exceed maximum allowed attempts! Please try again later.').show();
        else if(e.status==472)
        response_msg.html('Invalid Phone Number provided!').show();
        else if(e.status==481) 
        response_msg.html('Your pincode has expired. Please try again.').show();
        else if(e.status==514){
            $('#wait-modal').modal("show");
            get_wait_modal();}
        else
        response_msg.html('Something went wrong. Please try again later.').show(); //  Error code: '+e.status
        setBtnLoading(btn, false);
        ///location.reload();
    });
})

// Register Form Submit
$(document).on("submit", ".frmregister.frm2", function (e) {
    e.preventDefault();
    var form = $(this);
    var response_msg = form.find(".response-msg");
    var data = getFormData(form);
    
    data.data.refid = refid;
   
    data.data.subscription = 'free'; //$('.frmregister2').find('select[name="subscription"]').val();
  
    response_msg.hide();
    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);

    postRegister2OTP(data.data).then(res => {
        localStorage.removeItem("last_profile_edit");
        location.href = location.href.replace('/register','');
    }).catch(e => {
        console.log("e", e);
        if(e.status==471) //406 ?
        response_msg.html('Exceed maximum allowed attempts! Please try again later.').show();
        else if(e.status==514){
            $('#wait-modal').modal("show");
            get_wait_modal();}
        else
        response_msg.html('Something went wrong. Please try again later.').show(); //  Error code: '+e.status
        setBtnLoading(btn, false);
        ///location.reload();
    });
})


function secondForm(){
    var form = $('.frmregister3');
    
    var data = getFormData(form);
    
    // data.data.refid = refid;
   
    // data.data.subscription = $('.frmregister2').find('select[name="subscription"]').val();
  
    postRegister3OTP(data.data).then(res => {
        location.reload();
    }).catch(e => {
        console.log("e", e);
        if(e.status==514){
            $('#wait-modal').modal("show");
            get_wait_modal();}
        
        ///location.reload();
    });
}

// Edit Profile Form Submit
$(document).on("submit", "#edit-profile-form", function (e) {
    e.preventDefault();
    var form = $(this);
    var data = getFormData(form);

    // var email_regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    // if (!email_regex.test(String(data.data.email).toLowerCase())) {
    //     return;
    // }

    form.find(".error").remove();

    var bday = `${data.data.data_year}-${data.data.data_month}-${data.data.data_day}`;
    data.data.birthdate = bday;

    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);

    $.ajax({
        url: edit_profile_url,
        type: 'put',
        headers: {
            "X-CSRFToken": xtoken,
        },
        data: data.data,
    }).done(function (response) {
        window.location.reload();
    }).fail(function (e) {
        var error = JSON.parse(e.responseText);
        for (const key in error) {
            if (Object.hasOwnProperty.call(error, key)) {
                const er = error[key];
                console.log(key, er);
                form.find("[name='"+key+"']").closest(".input2").after('<small class="error">' + er[0] + '</small>');
            }
        }
        setBtnLoading(btn, false);
    });

})

// Send coins form submit
$(document).on("submit", "#send-coins-form", function (e) {
    e.preventDefault();
    var form = $(this);
    var form_data = getFormData(form);
    var response_msg = form.find(".response-msg");
    response_msg.hide();

    var btn = form.find("button[type=submit]");
    setBtnLoading(btn, true);

    const data = form_data.data;
    $.ajax({
        url: `/api/users/${data.friend}/send_coins/`,
        type: form_data.method,
        headers: {
            "X-CSRFToken": xtoken,
        },
        data: {
            amount: data.amount,
        }
    }).done(function (response) {
        setBtnLoading(btn, false);
        user_coins = user_coins - data.amount;
        $("#actual-user-coins, .user-coins").html(user_coins);
        response_msg.html("Coins are now transferred to your friend.").show();
        setTimeout(function(){ $("#send-coins").modal("hide");},3000);
        $('#user-coins').css('background','#EA2D2D');
    }).fail(function (ee) {
        response_msg.html("This amount exceeds your balance.").show();
        setBtnLoading(btn, false);
    });

})
