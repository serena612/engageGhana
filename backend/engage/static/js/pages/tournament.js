var participants_has_next = false;
var participants_page = 1;
var loading = false;

$(function () {
    // check device to put the right href link for practice button
    var practiceButton = $("#practice");
    var mobileOS = mobilecheck();
    
    if (mobileOS === "android") {
        practiceButton.attr("href", practiceButton.data("link-android"))
    } else if (mobileOS === 'ios') {
        practiceButton.attr("href", practiceButton.data("link-ios"))
    } else {
        practiceButton.attr("href", practiceButton.data("link-pc"));
    }

    if (tournament_slug) {
        //load participants
        get_participants().then(function (result) {
            if (result.pagination.has_next) {
                participants_has_next = true;
                participants_page += 1;
            } else {
                participants_has_next = false;
            }

            $("#participant_list").empty();

            var profile_mg = '/img/profile.png';
            var flag_img = '/img/usa.svg';

            if (result.data.length >= 1) {
                result.data.map((i) => {
                    $("#participant_list").append(`
                            <li>
                                <a class="left" href="/profile/${i?.participant?.uid}">
                                    <img src="${i.participant?.profile_image}"
                                         class="pro-img" alt="">
                                    <div class="img">
                                        <span class="rank">${big_number(i.participant.level)}</span>

                                        <img src="${i?.participant?.avatar || profile_mg}" alt="">
                                    </div>
                                </a>
                                <div class="right2">
                                    <div class="ll">
                                        <div class="location">
                                            <img src="${i?.participant?.flag || flag_img}" alt="flag" style="width: 40px"/>
                                        </div>
                                        <div class="location-cont">
                                            <span class="name">${i.participant.username}</span>
                                            <span>${i.participant.country}</span>
                                        </div>
    
                                    </div>
                                    <div class="btns">
                                        <a href="/profile/${i?.participant?.uid}" class="btn2 flat">Check Profile</a>
                                    </div>
                                </div>
                            </li>
                        `);
                })
            }
        }).catch(function (error) {
            console.log(error);
        });

        
        //load next page (participants pagination)
        // $(".profile-contain-friends .friends-list.grid").on("scroll", function () {
           
        //     var scrollTop = $(this).scrollTop();
        //     if ((scrollTop + $(this).innerHeight()) >= (this.scrollHeight - 30)) {
        //         if (!loading) {
        //             loading = true;
        //             if (participants_has_next) {
        //                 get_participants().then(function (result) {
        //                     if (result.pagination.has_next) {
        //                         participants_has_next = true;
        //                         participants_page += 1;
        //                     } else {
        //                         participants_has_next = false;
        //                     }

        //                     var profile_mg = 'img/profile.png';
        //                     var flag_img = 'img/usa.svg';

        //                     if (result.data.length >= 1) {
        //                         result.data.map((i) => {
        //                             $("#participant_list").append(`
        //                                     <li> 
        //                                         <a class="left" href="/profile/${i?.participant?.uid}">
        //                                             <img src="${i.participant?.profile_image}"
        //                                                 class="pro-img" alt="">
        //                                             <div class="img">
        //                                                 <span class="rank">${big_number(i.participant.level)}</span>

        //                                                 <img src="${i?.participant?.avatar || profile_mg}" alt="">
        //                                             </div>
        //                                         </a>
        //                                         <div class="right2">
        //                                             <div class="ll">
        //                                                 <div class="location">
        //                                                     <img src="${flag_img}" alt="">
        //                                                 </div>
        //                                                 <div class="location-cont">
        //                                                     <span class="name">${i.participant.username}</span>
        //                                                     <span>${i.participant.country}</span>
        //                                                 </div>
                    
        //                                             </div>
        //                                             <div class="btns">
        //                                                 <a href="/profile/${i?.participant?.uid}" class="btn2 flat">Check Profile</a>
        //                                             </div>
        //                                         </div>
        //                                     </li>
        //                                 `);
        //                         })
        //                     }

        //                     loading = false;
        //                 }).catch(function (error) {
        //                     loading = false;
        //                 });
        //             }
        //         }
        //     }
        // });

    }

    //handle set game account form submit
   
    $("#set-game-account").submit(function (e) {
        e.preventDefault();
        var btn = $(this).find("button[type=submit]");
        setBtnLoading(btn, true);
        $('#set-game-account').find('.error_msg').html('');
        var account = $('#set-game-account').find("input[name='account']").val();
        if(account=="" ||  account.trim()==""){
            btn.removeClass('is-loading');
            btn.removeAttr('disabled');
            $('#set-game-account').find('.error_msg').html('Nickname is not valid!')
            return;
        }
        if(account.length<=1){
            btn.removeClass('is-loading');
            btn.removeAttr('disabled');
            $('#set-game-account').find('.error_msg').html('Nickname length must be greater than 1!')
            return;
        }
        var serializedData = $(this).serialize();
        $.ajax({
            type: 'POST',
            url: set_game_account,
            headers: {
                "X-CSRFToken": xtoken,
            },
            data: serializedData,
            success: function (response) {
                $.ajax({
                    type: 'POST',
                    url: tournament_join.replace("$1", tournament_slug),
                    headers: {
                        "X-CSRFToken": xtoken,
                    },
                    success: function (response) {
                        $("#user-game-modal").modal("hide");
                       
                        if (response.code === 'waiting_list') {
                            $('#joinStatus').html('<a style="cursor: default" class="disabled">Waiting List</a>');
                            showInfoModal('Waiting List', '<p>You were added in the waiting list since the tournament is already full. You will be added automatically in case active users left the tournament.</p>')
                        } else {
                            update_joinedtrn();
                            $('#joinStatus').html('<a style="cursor: default">Joined <img src="/static/img/check.svg" class="joined-in" alt=""></a>');
                            showInfoModal("You're in!", "<p>You have joined the tournament successfully.</p>")
                        }
                        //setBtnLoading(btn, false);
                        $('#info-modal .btn3').click(function(){ location.reload();})
                       
                    },
                    error: function (response) {
                        $("#user-game-modal").modal("hide");
                        if(response.responseJSON.code === 'unbilled_user'){
                            showInfoModal('Recharge Line!', '<p>You don\'t have enough balance to join this tournament. Please recharge your line and try again.</p>');
                        } else if(response.responseJSON.code === 'free_user'){
                            showInfoModal('Error!', '<p>This tournament does not accept free users. Please <a href="/register">subscribe to Engage</a> in order to join.</p>');
                            //$('#upgrade-package-modal').modal('show');
                        } else if(response.responseJSON.code === 'minimum_profile_level'){
                            showInfoModal('Error!', '<p>You do not meet the minimum level requirement! Please try joining at a later time.</p>');
                        } else if(response.responseJSON.code === 'participant_exists'){
                            showInfoModal('Error!', '<p>You have already joined this tournament!</p>');
                        } else {
                            showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>');
                        }
                        setBtnLoading(btn, false);
                    }
                })
            },
            error: function (response) {
                showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
                setBtnLoading(btn, false);
                console.log(response);
            }
        })
    })


})


//handle upgrade subscription click
$("#upgrade-package-modal").on("click", function () {
    setBtnLoading($(this), true);
  
    function upgrade_subsp() {
        return new Promise((resolve, reject) => {
            $.ajax({
                url: upgrade_subscription.replace("user_uid", user_uid),
                headers: {
                    "X-CSRFToken": xtoken,
                },
                type: "post",
                data: {},
                error: function (value) {
                    reject(value);
                },
                success: function (value) {
                    value.is_sub
                        resolve(value);
                        if (value.is_sub == 'false')
                        {
                            window.location.href="/secured"
                        }
                        else{
                            $("#upgrade-package-modal").modal("hide");
                            setBtnLoading($("#upgrade-package-modal"), false);
                            window.location.reload(true);
                        }
                },
            });
        });
    }
  
    upgrade_subsp().then(function (_) {
        
        // $("#upgrade-package-modal").modal("hide");
        // setBtnLoading($("#upgrade-package-modal"), false);
        // window.location.reload(true);
    }).catch(function (error) {
      $("#upgrade-package-modal").modal("hide");
        setBtnLoading($("#upgrade-package-modal"), false);
        showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
    });
  });


$("#pay-btn").click(function (e) {
    setBtnLoading(this, true);

    $.ajax({
        type: 'POST',
        url: pay_fee_url,
        headers: {
            "X-CSRFToken": xtoken,
        },
        data: {},
        success: function (data) {
            setBtnLoading($("#pay-btn"), false);
            const coins = 30;
            $("#user-game-modal").modal("hide");
            const user_coins = parseInt($("#actual-user-coins").text()) - parseInt(coins);
            $("#actual-user-coins, .user-coins").html(user_coins);
            $("#user-game-new-modal").modal("show");

            if($("#set-game-new-account").length>0){
                $("#set-game-new-account").submit(function (e) {
                    e.preventDefault();
                    var btn = $(this).find("button[type=submit]");
                    setBtnLoading(btn, true);
            
                    var serializedData = $(this).serialize();
                    $.ajax({
                        type: 'POST',
                        url: set_game_account,
                        headers: {
                            "X-CSRFToken": xtoken,
                        },
                        data: serializedData,
                        success: function (response) {
                            $.ajax({
                                type: 'POST',
                                url: tournament_join.replace("$1", tournament_slug),
                                headers: {
                                    "X-CSRFToken": xtoken,
                                },
                                success: function (response) {
                                    $("#user-game-new-modal").modal("hide");
                                   
                                    if (response.code === 'waiting_list') {
                                        $('#joinStatus').html('<a style="cursor: default" class="disabled">Waiting List</a>');
                                        showInfoModal('Waiting List', '<p>You were added in the waiting list since the tournament is already full. You will be added automatically in case active users left the tournament.</p>')
                                    } else {
                                        $('#joinStatus').html('<a style="cursor: default">Joined <img src="/static/img/check.svg" class="joined-in" alt=""></a>');
                                        showInfoModal("You're in!", "<p>You have joined the tournament successfully.</p>")
                                        update_joinedtrn();
                                    }
                                    setBtnLoading(btn, false);
                                },
                                error: function (response) {
                                    $("#user-game-new-modal").modal("hide");
                                    
                                    if(response.responseJSON.code === 'unbilled_user'){
                                        showInfoModal('Error!', '<p>Your subscription has expired! Please renew it to join.</p>');
                                    } else if(response.responseJSON.code === 'free_user'){
                                        showInfoModal('Error!', '<p>This tournament does not accept free users. Please <a href="/register">subscribe to Engage</a> in order to join.</p>');
                                    } else if(response.responseJSON.code === 'minimum_profile_level'){
                                        showInfoModal('Error!', '<p>You do not meet the minimum level requirement! Please try joining at a later time.</p>');
                                    } else if(response.responseJSON.code === 'participant_exists'){
                                        showInfoModal('Error!', '<p>You have already joined this tournament!</p>');
                                    } else {
                                        showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>');
                                    }
                                    setBtnLoading(btn, false);
                                }
                            })
                        },
                        error: function (response) {
                            showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
                            setBtnLoading(btn, false);
                        }
                    })
                })
            }

        },
        error: function (response) {
            setBtnLoading($("#pay-btn"), false);
            var {
                responseText,
                status
            } = response;

            $("#user-game-modal").modal("hide");
            if (status === 406) {
                showPurchaseModal('Error!', `<p>${JSON.parse(responseText).detail}</p>`)
            } else {
                showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
            }
            
        }
    })
})

function update_joinedtrn() {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: update_joined_tournaments.replace("user_uid", user_uid),
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {},
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                value.is_sub
                    resolve(value);
            },
        });
    });
}

$('.register_btn').on("click", function () {
    function check_user_new_status() {
        $("#user-game-modal").modal("hide");
        return new Promise((resolve, reject) => {
            $.ajax({
                url: check_user_status.replace("user_uid", user_uid),
                headers: {
                    "X-CSRFToken": xtoken,
                },
                type: "post",
                data: {},
                error: function (value) {
                    reject(value);
                },
                success: function (value) {
                    resolve(value);
                    console.log("value",value,value.status);
                    //check if not same status
                    if(value.status != $('#userSub').val())
                    {
                        window.location.reload();
                    }
                    else {
                        $("#user-game-modal").modal("show"); 
                    }
                    
                },
            });
        });
    }
    check_user_new_status();
})

$('.btn_upgrade').on("click", function () {
    setBtnLoading($(this), true);
  
    function upgrade_subsp() {
        return new Promise((resolve, reject) => {
            $.ajax({
                url: upgrade_subscription.replace("user_uid", user_uid),
                headers: {
                    "X-CSRFToken": xtoken,
                },
                type: "post",
                data: {},
                error: function (value) {
                    reject(value);
                },
                success: function (value) {
                    value.is_sub
                        resolve(value);
                        if (value.is_sub == 'false')
                        {
                            window.location.href="/secured"
                        }
                },
            });
        });
    }
  
    upgrade_subsp().then(function (_) {
        
        $("#upgrade-package-modal").modal("hide");
        $("#upgrade-package-modal").find('.btn_upgrade').removeClass("is-loading");
        $("#upgrade-package-modal").find('.btn_upgrade').prop("disabled", false);


        $("#user-game-modal").modal("hide");
        $("#user-game-modal").find('.btn_upgrade').removeClass("is-loading");
        $("#user-game-modal").find('.btn_upgrade').prop("disabled", false);

        //window.location.reload(true);
    }).catch(function (error) {
      $("#upgrade-package-modal").modal("hide");
      $("#upgrade-package-modal").find('.btn_upgrade').removeClass("is-loading");
      $("#upgrade-package-modal").find('.btn_upgrade').prop("disabled", false);

      $("#user-game-modal").modal("hide");
      $("#user-game-modal").find('.btn_upgrade').removeClass("is-loading");
      $("#user-game-modal").find('.btn_upgrade').prop("disabled", false);
        showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
    });
  });
