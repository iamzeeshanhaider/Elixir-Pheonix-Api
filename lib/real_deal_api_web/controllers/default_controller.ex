defmodule RealDealApiWeb.DefaultController do
  use RealDealApiWeb, :controller

  def index(conn,_params) do
    text conn, "The Real Deal Api Live  -  #{Mix.env()}"
  end

end
