package main

import (
	"aayush/internal/models"
	"aayush/internal/validator"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
)

type snippetCreateForm struct {
	Title               string `form:"title"`
	Content             string `form:"content"`
	Expires             int    `form:"expires"`
	validator.Validator `form:"-"`
}
type userSignupForm struct {
	Name                string `form:"name"`
	Email               string `form:"email"`
	Password            string `form:"password"`
	validator.Validator `form:"-"`
}
type userLoginForm struct {
	Email               string `form:"email"`
	Password            string `form:"password"`
	validator.Validator `form:"-"`
}
type accountPasswordUpdateForm struct {
	CurrentPassword         string `form:"currentPassword"`
	NewPassword             string `form:"newPassword"`
	NewPasswordConfirmation string `form:"newPasswordConfirmation"`
	validator.Validator     `form:"-"`
}

func (app *application) home(w http.ResponseWriter, r *http.Request) {

	snippets, err := app.snippets.Latest()
	if err != nil {
		app.serverError(w, err)
		return
	}
	data := app.newTemplateData(r)
	data.Snippets = snippets
	app.render(w, http.StatusOK, "home.htm", data)

}
func (app *application) snippetView(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id, err := strconv.Atoi(params.ByName("id"))
	if err != nil || id < 1 {
		app.NotFound(w)
		return
	}
	snippet, err := app.snippets.Get(id)
	if err != nil {
		if errors.Is(err, models.ErrNoRecord) {
			app.NotFound(w)
		} else {
			app.serverError(w, err)
		}
		return
	}

	data := app.newTemplateData(r)
	data.Snippet = snippet
	app.render(w, http.StatusOK, "view.htm", data)

}
func (app *application) snippetCreate(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	data.Form = snippetCreateForm{
		Expires: 365,
	}
	app.render(w, http.StatusOK, "create.htm", data)
}
func (app *application) snippetCreatePost(w http.ResponseWriter, r *http.Request) {
	var form snippetCreateForm
	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	form.CheckField(validator.NotBlank(form.Title), "title", "This field cannot be blank")
	form.CheckField(validator.MaxChars(form.Title, 100), "title", "This field cannot be more than 100 characters long")
	form.CheckField(validator.NotBlank(form.Content), "content", "This field cannot be blank")
	form.CheckField(validator.PermittedValue(form.Expires, 1, 7, 365), "expires", "This field must equal 1, 7 or 365")

	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, http.StatusUnprocessableEntity, "create.htm", data)
	}

	id, err := app.snippets.Insert(form.Title, form.Content, form.Expires)
	if err != nil {
		app.serverError(w, err)
		return
	}
	//using session managenemt to show the message after creating new snippet
	app.sessionManager.Put(r.Context(), "flash", "Snippet successfully created!")

	http.Redirect(w, r, fmt.Sprintf("/snippet/view/%d", id), http.StatusSeeOther)
}
func (app *application) userSignup(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	data.Form = userSignupForm{}
	app.render(w, http.StatusOK, "signup.htm", data)
}
func (app *application) userSignupPost(w http.ResponseWriter, r *http.Request) {
	var form userSignupForm
	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	form.CheckField(validator.NotBlank(form.Name), "name", "This field cannot be blank")
	form.CheckField(validator.NotBlank(form.Email), "email", "This field cannot be blank")
	form.CheckField(validator.Matches(form.Email, validator.EmailRX), "email", "This field must be a valid email address")
	form.CheckField(validator.NotBlank(form.Password), "password", "This field cannot be blank")
	form.CheckField(validator.MinChars(form.Password, 8), "password", "This field must be at least 8 character long")
	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, http.StatusUnprocessableEntity, "signup.htm", data)
		return
	}
	err = app.users.Insert(form.Name, form.Email, form.Password)
	if err != nil {
		if errors.Is(err, models.ErrDuplicateEmail) {
			form.AddFieldError("email", "Email addresss is already in use")
			data := app.newTemplateData(r)
			data.Form = form
			app.render(w, http.StatusUnprocessableEntity, "signup.htm", data)
		} else {
			app.serverError(w, err)
		}
		return
	}
	app.sessionManager.Put(r.Context(), "flash", "Your signup was successful. Please log in.")
	http.Redirect(w, r, "/user/login", http.StatusSeeOther)
}
func (app *application) userLogin(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	data.Form = userLoginForm{}
	app.render(w, http.StatusOK, "login.htm", data)
	fmt.Fprintln(w, "Display a HTML form for logging in  a new user...")
}
func (app *application) userLoginPost(w http.ResponseWriter, r *http.Request) {
	var form userLoginForm
	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	form.CheckField(validator.NotBlank(form.Email), "email", "This field cannot be blank")
	form.CheckField(validator.Matches(form.Email, validator.EmailRX), "email", "This field must be a valid email address")
	form.CheckField(validator.NotBlank(form.Password), "password", "This field cannot be blank")

	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, http.StatusUnprocessableEntity, "login.htm", data)
		return
	}
	id, err := app.users.Authenticate(form.Email, form.Password)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			fmt.Println("inside models")
			form.AddNonFieldError("Email or Password is incorrect")
			data := app.newTemplateData(r)
			data.Form = form
			app.render(w, http.StatusUnprocessableEntity, "login.htm", data)
		} else {
			app.serverError(w, err)
		}
		return
	}
	err = app.sessionManager.RenewToken(r.Context())
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.sessionManager.Put(r.Context(), "authenticatedUserID", id)
	path := app.sessionManager.PopString(r.Context(), "redirectPathAfterLogin")
	if path != "" {
		http.Redirect(w, r, path, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/snippet/create", http.StatusSeeOther)
}
func (app *application) userLogoutPost(w http.ResponseWriter, r *http.Request) {
	err := app.sessionManager.RenewToken(r.Context())
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.sessionManager.Remove(r.Context(), "authenticatedUserID")
	app.sessionManager.Put(r.Context(), "flash", "You've been logged out successfully!")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (app *application) about(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	app.render(w, http.StatusOK, "about.htm", data)
}
func ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}
func (app *application) accountView(w http.ResponseWriter, r *http.Request) {
	userId := app.sessionManager.GetInt(r.Context(), "authenticatedUserID")
	user, err := app.users.Get(userId)
	if err != nil {
		if errors.Is(err, models.ErrNoRecord) {
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		} else {
			app.serverError(w, err)
		}
		return
	}
	data := app.newTemplateData(r)
	data.User = user
	app.render(w, http.StatusOK, "account.htm", data)
}
func (app *application) accountPasswordUpdate(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	data.Form = accountPasswordUpdateForm{}
	app.render(w, http.StatusOK, "password.htm", data)
}
func (app *application) accountPasswordUpdatePosts(w http.ResponseWriter, r *http.Request) {

	var form accountPasswordUpdateForm
	err := app.decodePostForm(r, &form)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	form.CheckField(validator.NotBlank(form.CurrentPassword), "currentPassword", "This field cannot be blank")
	form.CheckField(validator.NotBlank(form.NewPassword), "newPassword", "This field cannot be blank")
	form.CheckField(validator.MinChars(form.NewPassword, 8), "newPassword", "This field must be at least 8 character long")
	form.CheckField(validator.NotBlank(form.NewPasswordConfirmation), "newPasswordConfirmation", "This field cannot be blank")
	form.CheckField(form.NewPassword == form.NewPasswordConfirmation, "newPasswordConfirmation", "Passwords do not match")
	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, http.StatusUnprocessableEntity, "password.htm", data)
		return
	}
	userID := app.sessionManager.GetInt(r.Context(), "authenticatedUserID")
	err = app.users.PasswordUpdate(userID, form.CurrentPassword, form.NewPassword)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			form.AddFieldError("currentPassword", "Current password is incorrect")
			data := app.newTemplateData(r)
			data.Form = form
			app.render(w, http.StatusUnprocessableEntity, "password.htm", data)
		} else if err != nil {
			app.serverError(w, err)
		}
		return
	}
	app.sessionManager.Put(r.Context(), "flash", "Your password has been updated!")
	http.Redirect(w, r, "/account/view", http.StatusSeeOther)

}
